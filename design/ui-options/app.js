(() => {
  'use strict';
  const icons = {
    shield:'<path d="M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6z"/><path d="m8 12 3 3 5-6"/>',
    grid:'<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
    cert:'<rect x="5" y="3" width="14" height="17" rx="2"/><path d="M9 7h6M9 11h6"/><circle cx="12" cy="17" r="3"/><path d="m10 19-1 4 3-1 3 1-1-4"/>',
    clock:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    mail:'<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 6 9 7 9-7"/>',
    logs:'<rect x="5" y="3" width="14" height="18" rx="2"/><path d="M9 8h6M9 12h6M9 16h4"/>',
    lock:'<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/>',
    server:'<rect x="4" y="3" width="16" height="18" rx="2"/><path d="M4 12h16M8 7h1M8 16h1M13 7h3M13 16h3"/>',
    arrow:'<path d="m10 5 7 7-7 7M17 12H3"/>',
    back:'<path d="m10 5-7 7 7 7M3 12h17"/>',
    check:'<path d="m5 12 4 4L19 6"/>',
    refresh:'<path d="M20 7v5h-5M4 17v-5h5"/><path d="M6 7a7 7 0 0 1 12-1l2 6M4 12l2 6a7 7 0 0 0 12-1"/>',
    globe:'<circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18"/>',
    menu:'<path d="M4 6h16M4 12h16M4 18h16"/>',
    close:'<path d="m6 6 12 12M6 18 18 6"/>',
    chevron:'<path d="m8 10 4 4 4-4"/>',
    alert:'<path d="m12 3 10 18H2zM12 9v5M12 17h.01"/>',
    logout:'<path d="M9 3H4v18h5M10 12h11m-4-4 4 4-4 4"/>'
  };
  const icon = name => `<svg aria-hidden="true" viewBox="0 0 24 24">${icons[name] || icons.shield}</svg>`;
  const escape = value => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const nav = [['overview','grid','运行概览'],['certificate','cert','证书管理'],['renewal','clock','续期计划'],['notifications','mail','邮件通知'],['logs','logs','运行记录'],['security','lock','访问安全']];
  const state = {days:2,interval:'1',minute:17,email:'admin@example.com',success:true,failure:true,enabled:true,filter:'all',checked:false};
  const app = document.getElementById('app');
  const themeNames = {dsm:'A · DSM 经典',clear:'B · 简洁工作台',night:'C · 深色监控台'};
  let toastTimer, lastFocus;
  const badge = (text, kind='success') => `<span class="badge ${kind}"><i class="status-dot"></i>${text}</span>`;
  const btn = (text, action, glyph, primary=false) => `<button type="button" class="button${primary?' primary':''}" data-action="${action}">${glyph?icon(glyph):''}${text}</button>`;
  const field = (label, input, help='', full=false) => `<label class="field${full?' full':''}"><span>${label}</span>${input}${help?`<span class="help">${help}</span>`:''}</label>`;
  const toggle = (key, label, desc, enabled) => `<label class="setting-row"><span><strong>${label}</strong><p>${desc}</p></span><input class="switch" type="checkbox" name="${key}" aria-label="${label}" ${enabled?'checked':''}></label>`;
  const panel = (title, body, extra='', cls='') => `<section class="panel ${cls}"><div class="panel-heading"><h2 class="panel-title">${title}</h2>${extra}</div>${body}</section>`;
  const footer = () => `<footer class="page-footer"><span>${icon('lock')}目标部署：仅内网访问 · 外网禁止</span><span>示例数据 · 不连接群晖 · ${themeNames[document.body.dataset.theme]}</span></footer>`;
  function shell(page, content) {
    const title = nav.find(n=>n[0]===page)?.[2] || '运行概览';
    return `<div class="shell"><aside class="sidebar" aria-label="主导航"><a class="brand" href="#overview"><span class="brand-mark">${icon('shield')}</span><span><span class="brand-name">证书管家</span><span class="brand-subtitle" style="display:block">NAS CERTIFICATE MANAGER</span></span></a><div class="nav-label">工作空间</div><nav>${nav.map(([id,glyph,text])=>`<a class="nav-item ${page===id?'active':''}" href="#${id}" ${page===id?'aria-current="page"':''}><span class="nav-icon">${icon(glyph)}</span>${text}</a>`).join('')}</nav><div class="sidebar-footer"><div class="device-card">${icon('server')}<div><div class="device-name">Synology DS218+</div><div class="device-meta">证书自动化管理</div></div></div><a class="back-link" href="index.html">${icon('back')}返回风格选择</a></div></aside><main class="main"><header class="topbar"><button class="icon-button mobile-menu" data-action="menu" aria-label="展开导航" aria-expanded="false">${icon('menu')}</button><div class="breadcrumb"><span>我的 NAS</span><i>/</i><b>${title}</b></div><div class="topbar-actions"><span class="preview-tag">界面预览</span><a class="user-button" href="#login" aria-label="查看登录页面"><span class="avatar">A</span><span class="user-name">管理员</span>${icon('chevron')}</a></div></header><div class="page">${content}${footer()}</div></main></div><div id="toast" class="toast" role="status" hidden></div><div id="modal-root"></div>`;
  }
  function heading(title, subtitle, actions='', eyebrow='CERTIFICATE WORKSPACE') {
    return `<div class="page-heading"><div><p class="eyebrow">${eyebrow}</p><h1 class="page-title">${title}</h1><p class="page-subtitle">${subtitle}</p></div><div class="heading-actions">${actions}</div></div>`;
  }
  function nextCheck() {
    for(let hour=0;hour<48;hour+=Number(state.interval)){
      if(hour*60+state.minute>15*60+17)return (hour>=24?'明天 ':'')+String(hour%24).padStart(2,'0')+':'+String(state.minute).padStart(2,'0');
    }
    return '待安排';
  }
  function overview() {
    const activity = [
      ['15:17','定时检查完成','证书剩余 89 天，暂不需要续期'],
      ['14:17','定时检查完成','HTTPS 校验通过，服务证书一致'],
      ['10:04','证书替换成功','证书部署并验证通过，已发送成功通知']
    ];
    return heading('运行概览','查看证书状态，掌握每一次自动续期。',btn('运行记录','logs','logs')+btn('立即检查','check','refresh',true))+
    `<div class="dashboard"><section class="hero-panel"><div class="hero-copy"><div class="hero-kicker">${icon('cert')}当前管理的证书 ${badge('运行正常')}</div><h2 class="hero-domain">ttxli.cn</h2><p class="domain-alias">同时保护 www.ttxli.cn</p><div class="hero-footer"><span>${icon('shield')}Let's Encrypt</span><span>${icon('clock')}2027-01-28 到期</span><span>${icon('server')}已部署到群晖</span></div></div><div class="hero-countdown"><div class="countdown-number">89<span>天</span></div><p class="countdown-label">距离证书到期</p><div class="lifetime-bar"><div class="lifetime-fill"></div></div></div></section><div class="metric-row"><section class="metric-card"><div class="metric-icon">${icon('refresh')}</div><div class="metric-label">续期触发时间</div><div class="metric-value">提前 ${state.days}<span>天</span></div><div class="metric-note">按实际到期时间计算</div></section><section class="metric-card"><div class="metric-icon">${icon('clock')}</div><div class="metric-label">下一次自动检查</div><div class="metric-value">${state.enabled?nextCheck():'已暂停'}</div><div class="metric-note">${state.enabled?'每 '+state.interval+' 小时检查一次':'可在续期计划中开启'}</div></section><section class="metric-card"><div class="metric-icon">${icon('mail')}</div><div class="metric-label">邮件通知</div><div class="metric-value">${state.success&&state.failure?'成功 / 失败':state.success?'仅成功':state.failure?'仅失败':'已关闭'}</div><div class="metric-note">日常检查不打扰</div></section></div>${panel('自动续期流程',`<div class="flow">${[['检查到期时间','每小时自动执行'],['DNSPod 验证','自动创建验证记录'],['申请新证书',"Let’s Encrypt 签发"],['替换并校验','确认 HTTPS 生效'],['发送通知','成功与失败提醒']].map(([title,note],i)=>`<div class="flow-step"><span class="step-number">${i===0?icon('check'):String(i+1).padStart(2,'0')}</span><div><div class="step-title">${title}</div><div class="step-note">${i===0?`每 ${state.interval} 小时执行`:note}</div></div></div>`).join('')}</div>`,`<span class="panel-meta">自动运行，无需值守</span>`)}<div class="dashboard-bottom">${panel('最近活动',`<div class="activity-list">${activity.map(([time,title,note])=>`<div class="activity-item"><span class="activity-icon">${icon('check')}</span><div class="activity-text">${title}<small>${note}</small></div><time class="activity-time">${time}</time></div>`).join('')}</div>`,`<a href="#logs" class="button subtle">查看全部 ${icon('arrow')}</a>`)}${panel('部署与验证',`<div class="detail-list"><div class="detail-row"><span class="detail-label">部署目标</span><span class="detail-value">Synology DS218+</span></div><div class="detail-row"><span class="detail-label">证书服务</span><span class="detail-value">DSM · HTTPS</span></div><div class="detail-row"><span class="detail-label">证书链 / 域名</span><span class="detail-value good">验证通过</span></div><div class="detail-row"><span class="detail-label">DNS 验证记录</span><span class="detail-value">已清理</span></div><div class="detail-row"><span class="detail-label">最近检查</span><span class="detail-value" id="last-check">${state.checked?'刚刚完成':'今天 15:17:02'}</span></div></div>`,badge('状态正常'))}</div></div>`;
  }
  function settingsFrame(content, aside) {
    return `<div class="settings-layout"><div>${content}</div><aside class="panel side-note"><div class="panel-body">${aside}</div></aside></div>`;
  }
  function actions() { return `<div class="form-actions"><span class="save-note">修改仅在本次预览中生效</span><button type="reset" class="button">重置更改</button><button type="submit" class="button primary">保存配置</button></div>`; }
  function certificate() {
    return heading('证书管理','管理域名验证与部署目标，凭据始终隐藏。')+settingsFrame(`<form data-form="certificate" class="form-stack">${panel('证书信息',`<div class="panel-body form-grid">${field('证书描述','<input class="input" value="TencentCloud Certificate" disabled>')}${field('签发机构','<input class="input" value="Let’s Encrypt" disabled>')}${field('覆盖的域名','<div class="tag-list"><span class="badge neutral">ttxli.cn</span><span class="badge neutral">www.ttxli.cn</span></div>','更新现有证书时保留服务绑定。',true)}</div>`)}${panel('DNSPod 域名验证',`<div class="panel-body form-grid">${field('SecretId','<input class="input" type="password" disabled value="preview-only">','已配置 · 不回显原始凭据')}${field('SecretKey','<input class="input" type="password" disabled value="preview-only">','已配置 · 不回显原始凭据')}<div class="field full"><div>${btn('更换 DNS 凭据','credential','lock')}</div></div></div>`,badge('已配置'))}${panel('HTTPS 验证目标',`<div class="panel-body form-grid">${field('域名','<input class="input" value="ttxli.cn" disabled>')}${field('HTTPS 端口','<input class="input" value="5001" disabled>')}<p class="help field full">证书替换后，检查证书链、域名和实际服务证书是否一致。</p></div>`)}${actions()}</form>`,`<h3>自动验证，自动部署</h3><p>通过 DNSPod API 完成 DNS 验证，无需开放公网 80 端口。</p><p>证书签发后替换群晖当前证书，并验证实际 HTTPS 服务。</p><div class="notice">设计预览不会读取或保存真实密钥。</div>`);
  }
  function renewal() {
    return heading('续期计划','设置检查频率，以及距离到期多久开始申请新证书。')+settingsFrame(`<form data-form="renewal" class="form-stack">${panel('自动检查',`<div class="panel-body">${toggle('enabled','启用自动检查','定时检查证书，有需要时自动续期。',state.enabled)}</div>`)}${panel('检查与续期规则',`<div class="panel-body form-grid">${field('提前续期时间',`<div class="field-unit"><input class="input" name="days" type="number" min="1" max="30" value="${state.days}" required><span>天</span></div>`,'按证书实际到期时间计算，2 天即 48 小时。',true)}${field('检查频率',`<select class="input" name="interval">${[1,2,3,6,12].map(v=>`<option value="${v}" ${String(v)===state.interval?'selected':''}>每 ${v} 小时</option>`).join('')}</select>`)}${field('检查分钟',`<div class="field-unit"><input class="input" name="minute" type="number" min="0" max="59" value="${state.minute}" required><span>分</span></div>`)}<div class="field full"><div class="notice">当前规则：到期前 ${state.days} 天进入续期窗口，每 ${state.interval} 小时的第 ${state.minute} 分检查一次。</div></div></div>`)}${panel('异常处理',`<div class="panel-body"><div class="setting-row"><span><strong>保留当前有效证书</strong><p>新证书申请或部署失败时保留原证书。</p></span>${badge('保留')}</div><div class="setting-row"><span><strong>下次检查继续重试</strong><p>记录失败阶段，后续检查恢复未完成操作。</p></span>${badge('自动')}</div></div>`)}${actions()}</form>`,`<h3>检查不等于续期</h3><p>每次检查都会确认有效期，只有进入续期窗口才申请新证书。</p><p>续期、部署、HTTPS 校验和 DNS 清理完成后才算成功。</p><div class="notice">时区：Asia/Shanghai<br>示例到期日：2027-01-28</div>`);
  }
  function notifications() {
    return heading('邮件通知','重要结果及时送达，正常检查保持安静。',btn('预览测试邮件','mail-preview','mail'))+settingsFrame(`<form data-form="notifications" class="form-stack">${panel('收件人',`<div class="panel-body form-grid">${field('通知邮箱',`<input class="input" name="email" type="email" autocomplete="off" value="${escape(state.email)}" required>`,'续期成功和失败通知将发送到此邮箱。',true)}</div>`)}${panel('通知时机',`<div class="panel-body">${toggle('success','续期并替换成功','新证书部署并验证生效后发送一封通知。',state.success)}${toggle('failure','任何阶段执行失败','包含失败阶段、脱敏摘要、错误码和日志位置。',state.failure)}<div class="setting-row"><span><strong>普通检查</strong><p>未进入续期窗口、运行正常时不发送通知。</p></span><span class="badge neutral">不通知</span></div></div>`)}${panel('邮件内容',`<div class="panel-body"><div class="notice">ttxli.cn 证书续期成功<br>新证书已完成部署，HTTPS 验证通过。<br>证书到期时间：2027-01-28 09:04:56</div></div>`)}${actions()}</form>`,`<h3>只在需要时提醒</h3><p>成功邮件确认新证书已在服务中生效。</p><p>失败邮件说明是哪一步出错，并提供排查线索。</p><div class="notice">预览测试邮件仅展示样式，不会实际发送邮件。</div>`);
  }
  const records = [
    {at:'2026-10-30 15:17:02',type:'检查',stage:'有效期检查',result:'暂不需要续期',ok:true},
    {at:'2026-10-30 14:17:02',type:'检查',stage:'HTTPS 验证',result:'验证通过',ok:true},
    {at:'2026-10-30 10:04:36',type:'续期',stage:'完成',result:'已替换并通知',ok:true},
    {at:'2026-10-29 09:17:08',type:'续期',stage:'DNSPod 创建验证记录',result:'权限不足',ok:false}
  ];
  function logRows() {
    const items=records.filter(r=>state.filter==='all'||(state.filter==='failures'&&!r.ok));
    if(state.filter==='empty') return `<div class="empty-state">${icon('logs')}<h3>这段时间暂无运行记录</h3><p>定时检查或手动检查完成后，记录会显示在这里。</p>${btn('查看全部记录','all-logs','back')}</div>`;
    return `<div class="table-wrap"><table><thead><tr><th>执行时间</th><th>类型</th><th>执行阶段</th><th>结果</th><th>操作</th></tr></thead><tbody>${items.map(r=>`<tr><td class="mono">${r.at}</td><td>${r.type}</td><td>${r.stage}</td><td>${badge(r.result,r.ok?'success':'warning')}</td><td><button class="text-button" data-action="${r.ok?'record':'failure'}">查看详情</button></td></tr>`).join('')}</tbody></table></div>`;
  }
  function logs() {
    return heading('运行记录','查看检查、续期和部署结果，快速定位失败阶段。',btn('查看空状态','empty-logs','logs'))+panel('任务执行记录',`<div class="table-toolbar"><div class="segmented"><button data-action="all-logs" class="${state.filter==='all'?'active':''}">全部记录</button><button data-action="failed-logs" class="${state.filter==='failures'?'active':''}">仅失败</button></div><span class="panel-meta">示例数据 · 最近 30 天</span></div>${logRows()}`);
  }
  function security() {
    const rows=[['globe','仅内网访问','管理入口限制在指定内网网段，拒绝公网来源。'],['lock','登录与会话','密码登录、失败次数限制、闲置退出和会话撤销。'],['shield','浏览器请求保护','HTTPS、跨站请求防护和来源校验。'],['server','最小权限运行','管理容器与证书执行权限分离，限制可执行操作。'],['logs','敏感信息保护','密钥不回显，日志脱敏，记录关键配置修改。']];
    return heading('访问安全','仅限内网管理，关键操作需要身份验证。',btn('查看登录页','login','lock'))+settingsFrame(panel('安全机制规划',`<div class="panel-body safety-list">${rows.map(([glyph,title,desc])=>`<div class="setting-row"><span class="security-icon">${icon(glyph)}</span><span class="security-copy"><strong>${title}</strong><p>${desc}</p></span><span class="badge neutral">待实施</span></div>`).join('')}</div>`,'<span class="panel-meta">部署时实施并验证</span>'),`<h3>访问边界</h3><p>局域网内的设备可以打开管理页面；外网不能访问。</p><p>NAS 仍需访问外网完成 DNSPod 验证、证书签发及邮件发送。</p><div class="notice">此页面用于展示安全设置布局，尚未修改任何网络规则。</div>`);
  }
  function login() {
    return `<div class="login-page"><section class="login-art"><a class="login-return" href="index.html">${icon('back')}返回风格选择</a><div class="brand-mark">${icon('shield')}</div><p class="eyebrow">NAS CERTIFICATE MANAGER</p><h1>每一张证书，<br>安心交给自动化。</h1><p>从域名验证到证书部署，让 NAS 的 HTTPS 服务始终有序运行。</p><div class="login-graphic"><span>${icon('globe')}</span><i></i><span>${icon('cert')}</span><i></i><span>${icon('server')}</span></div><div class="login-preview">${icon('lock')}仅内网管理 · 管理员登录</div></section><section class="login-panel"><form class="login-form" data-form="login"><h2 class="login-brand">登录证书管家</h2><p>管理你的群晖证书与自动续期任务</p>${field('管理员账号','<input class="input" value="admin" disabled autocomplete="off">')}${field('登录密码','<input class="input" type="password" placeholder="预览无需输入密码" disabled autocomplete="off">')}<button type="submit" class="button primary">进入预览 ${icon('arrow')}</button><p class="help">当前为界面设计预览，无需输入真实密码。<br>正式版本将启用账号和密码验证。</p></form></section></div>`;
  }
  function render() {
    closeModal();
    const route = location.hash.slice(1) || 'overview';
    const views={overview,certificate,renewal,notifications,logs,security};
    app.innerHTML=route==='login'?login():shell(views[route]?route:'overview',(views[route]||overview)());
    document.title=`${route==='login'?'登录':nav.find(n=>n[0]===route)?.[2]||'运行概览'} · ${themeNames[document.body.dataset.theme]} · 证书管家`;
  }
  function toast(message) {
    clearTimeout(toastTimer);
    const node=document.getElementById('toast'); if(!node) return;
    node.textContent=message;node.hidden=false;
    toastTimer=setTimeout(()=>{node.hidden=true;},3600);
  }
  function modal(title,content) {
    lastFocus=document.activeElement;
    document.getElementById('modal-root').innerHTML=`<div class="modal-backdrop"><section class="modal" role="dialog" aria-modal="true" aria-labelledby="dialog-title"><div class="panel-heading"><h2 id="dialog-title">${title}</h2><button class="icon-button" data-action="close" aria-label="关闭">${icon('close')}</button></div><div class="panel-body">${content}</div><div class="modal-footer">${btn('关闭','close')}</div></section></div>`;
    document.body.style.overflow='hidden';
    document.querySelector('.modal button').focus();
  }
  function closeModal() {
    const node=document.getElementById('modal-root'); if(node) node.innerHTML='';
    document.body.style.overflow='';
    if(lastFocus?.isConnected)lastFocus.focus();
    lastFocus=null;
  }
  document.addEventListener('click',async event=>{
    const target=event.target.closest('[data-action]');if(!target)return;
    const action=target.dataset.action;
    if(['logs','login'].includes(action)){location.hash=action;return;}
    if(action==='menu'){const open=document.querySelector('.sidebar').classList.toggle('open');target.setAttribute('aria-expanded',String(open));return;}
    if(action==='close'){closeModal();return;}
    if(action==='check'){
      const previous=target.innerHTML;target.disabled=true;target.innerHTML=`<span class="spinning">${icon('refresh')}</span>检查中…`;
      try{await new Promise(resolve=>setTimeout(resolve,900));state.checked=true;const node=document.getElementById('last-check');if(node)node.textContent='刚刚完成';toast('预览检查完成：证书有效，暂不需要续期。');}
      catch{toast('预览检查未完成，请重试。');}
      finally{target.disabled=false;target.innerHTML=previous;}return;
    }
    if(['all-logs','failed-logs','empty-logs'].includes(action)){state.filter={'all-logs':'all','failed-logs':'failures','empty-logs':'empty'}[action];render();return;}
    if(action==='failure'){modal('失败记录详情',`<div class="notice">失败阶段：DNSPod 创建验证记录<br>错误摘要：当前子账号无权添加域名验证记录。<br>错误码：UnauthorizedOperation</div><div class="detail-list"><div class="detail-row"><span class="detail-label">发生时间</span><span>2026-10-29 09:17:08</span></div><div class="detail-row"><span class="detail-label">错误处理</span><span>保留当前证书，下次检查重试</span></div></div><pre class="event-log">[09:17:02] 开始检查证书有效期\n[09:17:04] 进入续期窗口\n[09:17:08] DNSPod 创建验证记录失败\n[09:17:08] 敏感凭据已隐藏\n\n失败记录：state/failures/example-failure/\n建议：检查子账号对目标域名的解析权限。</pre><p class="help">此记录仅用于展示失败分类和脱敏日志样式。</p>`);return;}
    if(action==='record'){modal('执行记录详情',`<div class="notice">执行结果：成功<br>HTTPS 服务证书与部署证书一致。<br>DNS 验证记录已清理。</div><pre class="event-log">示例运行记录\n✓ 有效期检查\n✓ HTTPS 证书链验证\n✓ 域名与证书指纹校验\n✓ 无待恢复操作</pre>`);return;}
    if(action==='mail-preview'){modal('测试邮件预览',`<div class="detail-list"><div class="detail-row"><span class="detail-label">收件人</span><span class="detail-value">${escape(state.email)}</span></div><div class="detail-row"><span class="detail-label">主题</span><span class="detail-value">ttxli.cn 证书续期成功</span></div></div><div class="notice">ttxli.cn 的新证书已完成替换。<br>HTTPS 证书链、域名和服务证书验证通过。<br>到期时间：2027-01-28 09:04:56<br><br>这是一封界面预览邮件，不会实际发送。</div>`);return;}
    if(action==='credential'){modal('更换 DNSPod 凭据',`<div class="form-grid">${field('SecretId','<input class="input" disabled placeholder="正式版本在此输入新 SecretId">','留空将保留现有凭据。',true)}${field('SecretKey','<input class="input" disabled type="password" placeholder="正式版本在此输入新 SecretKey">','保存后不回显密钥。',true)}<p class="notice field full">设计预览不接收真实凭据。正式版本会通过 HTTPS 提交并限制配置文件访问。</p></div>`);}
  });
  document.addEventListener('submit',event=>{
    const form=event.target.closest('[data-form]');if(!form)return;event.preventDefault();
    if(form.dataset.form==='login'){location.hash='overview';return;}
    const data=new FormData(form);
    if(form.dataset.form==='renewal'){state.days=Number(data.get('days'));state.interval=String(data.get('interval'));state.minute=Number(data.get('minute'));state.enabled=data.has('enabled');}
    if(form.dataset.form==='notifications'){state.email=String(data.get('email')).trim();state.success=data.has('success');state.failure=data.has('failure');}
    render();toast('已保存预览配置；群晖上的设置未修改。');
  });
  document.addEventListener('keydown',event=>{
    const dialog=document.querySelector('.modal');if(!dialog)return;
    if(event.key==='Escape'){closeModal();return;}
    if(event.key==='Tab'){const nodes=[...dialog.querySelectorAll('button,a,input:not(:disabled),select:not(:disabled),[tabindex="0"]')];const first=nodes[0],last=nodes.at(-1);if(event.shiftKey&&document.activeElement===first){event.preventDefault();last.focus();}else if(!event.shiftKey&&document.activeElement===last){event.preventDefault();first.focus();}}
  });
  window.addEventListener('hashchange',()=>{render();window.scrollTo(0,0);});
  render();
})();
