"""只认领精确指向本工具的任务；新建任务在安装验收前保持停用。"""
import copy
import json
import os
from pathlib import Path
import re
import shlex
import uuid

if __package__:
    from .host_bridge import Scheduler, atomic_bytes, canonical, private_directory, safe_file
else:
    from host_bridge import Scheduler, atomic_bytes, canonical, private_directory, safe_file


class TaskSetup:
    def __init__(self, native_home, scheduler=None, state_path=None, uid=0):
        self.home = Path(native_home)
        if not self.home.is_absolute() or self.home != self.home.resolve():
            raise ValueError('证书工具目录必须为无符号链接的绝对路径')
        self.scheduler = scheduler or Scheduler(self.home)
        self.state_path = Path(state_path) if state_path else self.home / 'state/setup-task.json'
        self.uid = uid

    def load(self):
        private_directory(self.state_path.parent, self.uid)
        if not os.path.lexists(self.state_path):
            return None
        value = json.loads(safe_file(self.state_path, uid=self.uid))
        if (not isinstance(value, dict) or set(value) != {'version', 'home', 'phase', 'name', 'task_id', 'expected'}
                or value['version'] != 1 or value['home'] != str(self.home)
                or value['phase'] not in ('prepared', 'creating', 'created', 'enabled', 'adopted')
                or not isinstance(value['name'], str) or not value['name']
                or (value['expected'] is not None and not isinstance(value['expected'], dict))
                or (value['task_id'] is not None and
                    (type(value['task_id']) is not int or not 1 <= value['task_id'] <= 2147483647))):
            raise ValueError('安装任务恢复记录无效，请检查私有安装目录')
        return value

    def save(self, state):
        private_directory(self.state_path.parent, self.uid)
        atomic_bytes(self.state_path, canonical(state))

    def read(self, identifier):
        task = self.scheduler.api('SYNO.Core.TaskScheduler', 'get', 4, {'id': identifier})
        return Scheduler(self.home, task_id=identifier).validate(task)

    def discover(self):
        start, identifiers, found = 0, set(), []
        while True:
            page = self.scheduler.api('SYNO.Core.TaskScheduler', 'list', 3, {'start': start, 'limit': 100})
            if (not isinstance(page, dict) or not isinstance(page.get('tasks'), list)
                    or type(page.get('total')) is not int or not 0 <= page['total'] <= 10000):
                raise ValueError('无法识别群晖任务列表')
            tasks = page['tasks']
            if not tasks and start < page['total']:
                raise ValueError('群晖任务列表不完整')
            for item in tasks:
                identifier = item.get('id') if isinstance(item, dict) else None
                if type(identifier) is not int or not 1 <= identifier <= 2147483647 or identifier in identifiers:
                    raise ValueError('群晖任务列表 ID 不正确或重复')
                identifiers.add(identifier)
                if item.get('owner') != 'root' or item.get('type') not in (None, 'script'):
                    continue
                task = self.scheduler.api('SYNO.Core.TaskScheduler', 'get', 4, {'id': identifier})
                if not isinstance(task, dict) or task.get('id') != identifier:
                    raise ValueError('群晖任务详情与列表不一致')
                script = task.get('extra', {}).get('script') if isinstance(task.get('extra'), dict) else None
                try:
                    matches = isinstance(script, str) and shlex.split(script) == ['/bin/sh', str(self.home / 'run-task.sh')]
                except ValueError:
                    matches = False
                if matches:
                    found.append(Scheduler(self.home, task_id=identifier).validate(task))
            start += len(tasks)
            if start >= page['total']:
                break
        if len(found) > 1:
            raise ValueError('发现多个执行本工具的任务，请先在 DSM 中核对，安装器不会重复创建或删除任务')
        return found

    def ensure(self, email, real_owner='root'):
        if (not isinstance(email, str) or email.startswith('-') or len(email) > 254
                or re.fullmatch(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}', email) is None
                or not isinstance(real_owner, str) or re.fullmatch(r'[A-Za-z0-9_.@-]{1,128}', real_owner) is None):
            raise ValueError('任务通知邮箱或管理账号无效')
        state = self.load()
        found = self.discover()
        if found:
            task = found[0]
            if state is None:
                state = {'version': 1, 'home': str(self.home), 'phase': 'adopted', 'name': task['name'], 'task_id': task['id'], 'expected': None}
            elif state['phase'] in ('prepared', 'creating'):
                expected = state['expected']
                if (task['name'] != state['name'] or not isinstance(expected, dict)
                        or task['enable'] or task['schedule'] != expected.get('schedule')
                        or task['extra'] != expected.get('extra')):
                    raise ValueError('创建期间出现其他同脚本任务，请先核对，安装器不会认领')
                state.update(phase='created', task_id=task['id'])
            elif state['task_id'] != task['id'] or state['name'] != task['name']:
                raise ValueError('任务与安装恢复记录不一致')
            self.save(state)
            return task
        if state and state['phase'] != 'prepared':
            raise ValueError('上次创建结果尚未确认或原任务已消失，请先在 DSM 核对；不会再次创建')
        if state is None:
            state = {'version': 1, 'home': str(self.home), 'phase': 'prepared',
                     'name': '证书管家自动续期-' + uuid.uuid4().hex[:16], 'task_id': None, 'expected': None}
            self.save(state)
        defaults = self.scheduler.api('SYNO.Core.TaskScheduler', 'get', 4,
                                      {'id': -1, 'type': 'script', 'real_owner': real_owner})
        if (not isinstance(defaults, dict) or defaults.get('id') != -1
                or defaults.get('type') != 'script' or defaults.get('owner') != 'root'
                or not isinstance(defaults.get('schedule'), dict) or not isinstance(defaults.get('extra'), dict)):
            raise ValueError('群晖未提供可识别的脚本任务默认模板')
        schedule = copy.deepcopy(defaults['schedule'])
        # 沿用 DSM 日期字段；仅新建任务默认每天 03:18 检查。
        schedule.update(date_type=0, hour=3, last_work_hour=3, minute=18, monthly_week=[],
                        repeat_date=1001, repeat_hour=0, repeat_hour_store_config=None,
                        repeat_min=0, repeat_min_store_config=None, version=4, week_day='0,1,2,3,4,5,6')
        extra = copy.deepcopy(defaults['extra'])
        extra.update(script='/bin/sh ' + shlex.quote(str(self.home / 'run-task.sh')),
                     notify_enable=True, notify_if_error=True, notify_mail=email)
        params = {'name': state['name'], 'owner': 'root', 'real_owner': defaults.get('real_owner') or real_owner,
                  'enable': False, 'type': 'script', 'schedule': schedule, 'extra': extra}
        state.update(phase='creating', expected=params)
        self.save(state)
        self.scheduler.api('SYNO.Core.TaskScheduler.Root', 'create', 4, params)
        found = self.discover()
        if not found or found[0]['name'] != state['name']:
            raise ValueError('任务创建回读尚未确认，请重新运行安装命令检查；不会重复创建')
        task = found[0]
        if task['enable'] or task['schedule'] != schedule or task['extra'] != extra:
            raise ValueError('新任务的计划、通知或停用状态回读不一致')
        state.update(phase='created', task_id=task['id'])
        self.save(state)
        return task

    def activate(self, identifier):
        state = self.load()
        if state is None or state['task_id'] != identifier:
            raise ValueError('没有与当前任务匹配的安装恢复记录')
        found = self.discover()
        if not found or found[0]['id'] != identifier or found[0]['name'] != state['name']:
            raise ValueError('任务归属已变化，停止启用')
        task = found[0]
        if state['phase'] in ('adopted', 'enabled'):
            return task
        if state['phase'] != 'created':
            raise ValueError('任务尚未完成创建确认')
        expected = state['expected']
        if (not isinstance(expected, dict) or task['schedule'] != expected.get('schedule')
                or task['extra'] != expected.get('extra')):
            raise ValueError('新任务计划或通知已发生变化，停止自动启用')
        if not task['enable']:
            task = copy.deepcopy(task)
            task['enable'] = True
            scheduler = Scheduler(self.home, task_id=identifier)
            scheduler.api = self.scheduler.api
            task = scheduler.put(task)
        state['phase'] = 'enabled'
        self.save(state)
        return task
