<script setup lang="ts">
import { reactive, watch } from 'vue'
import { Button, Form, Input, Modal } from 'ant-design-vue'
import type { StepUpChallenge } from '../types'
import NoticeBar from './NoticeBar.vue'
const FormItem = Form.Item
const props = defineProps<{
  open: boolean; busy: boolean; error: string; operation: string
  challenge: StepUpChallenge | null; expiresIn: number; resendAfter: number
  recoverSend: boolean; verifyUnknown: boolean
}>()
const emit = defineEmits<{ send: []; resend: []; verify: [code: string]; cancel: [] }>()
const form = reactive({ code: '' })
watch(() => [props.open, props.challenge?.challenge_id], () => { form.code = '' })
function submit() {
  const value = form.code
  form.code = ''
  emit('verify', value)
}
</script>
<template>
  <Modal :open="open" title="敏感操作二次验证" :footer="null" :mask-closable="false" :keyboard="false" :destroy-on-close="true" @cancel="emit('cancel')">
    <p>即将执行：<strong>{{ operation }}</strong></p>
    <p>本次验证码仅授权当前操作。取消验证不会执行操作，自动续期仍按计划运行。</p>
    <NoticeBar v-if="error" type="error">{{ error }}</NoticeBar>
    <template v-if="!verifyUnknown">
      <p v-if="challenge">验证码发送至 {{ challenge.email_masked || '已绑定登录邮箱' }}。</p>
      <NoticeBar v-if="challenge && !recoverSend" :type="expiresIn > 0 ? 'info' : 'warning'">
        {{ expiresIn > 0 ? `验证码 ${expiresIn} 秒内有效` : '验证码已过期或暂不可用，请重新发送。' }}
      </NoticeBar>
      <Button v-if="!challenge || recoverSend" type="primary" :loading="busy" :disabled="busy" @click="emit('send')">
        {{ recoverSend ? '重新确认验证状态' : '发送本次操作验证码' }}
      </Button>
      <Form v-else :model="form" layout="vertical" :required-mark="false" @finish="submit">
        <FormItem name="code" label="邮箱验证码" html-for="stepup-code">
          <Input id="stepup-code" v-model:value="form.code" name="stepup_code" inputmode="numeric" autocomplete="one-time-code" :maxlength="6" :disabled="busy || expiresIn <= 0" />
        </FormItem>
        <div class="cert-security-actions">
          <Button type="primary" html-type="submit" :loading="busy" :disabled="busy || expiresIn <= 0">验证并执行本次操作</Button>
          <Button :disabled="busy || resendAfter > 0" @click="emit('resend')">{{ resendAfter > 0 ? `${resendAfter} 秒后可重新发送` : '重新发送验证码' }}</Button>
        </div>
      </Form>
    </template>
    <div class="cert-stepup-cancel"><Button @click="emit('cancel')">取消本次操作</Button></div>
  </Modal>
</template>
