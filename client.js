/**
 * Client half of dsh-access-gateway: the Settings section.
 *
 * One section, no build step, and the same primitives the built-in Settings
 * sections use, so the fields, the hints and the single Save button are the
 * application's own components rather than a look-alike.
 *
 * The page reads the live entry state over the Host route and edits the
 * address, the port, the session lifetime and the gateway password in one form.
 * The switch is stored with the rest of the settings, and a password the Host
 * generated is shown so it can be copied; the store itself keeps only its hash.
 */
window.__ModuleLoader__.load({
  id: 'dsh-access-gateway',
  factory(require) {
    const React = require('react')
    const { useCallback, useEffect, useState } = React
    const h = React.createElement
    const { Button, SettingsForm, SettingsSecretField, SettingsValueField, Switch } = require('@deepseek-ai/dsh-client-ui-primitives')

    /** Locale namespace of this plugin's copy. */
    const NS = 'dshAccessGateway'

    /** Absolute route the Host half serves. */
    const RPC_PATH = '/dsh-access-gateway/rpc'

    /** Simplified Chinese copy. */
    const zh = {
      section: '访问入口',
      intro: '在局域网中访问这个 Web GUI。同一个 Wi-Fi 下，手机或另一台电脑打开下面的入口地址，输一次密码就能进；通过后自动带上启动 token 跳转，之后按设定的天数免密。密码默认开启，首次启动时由宿主随机生成一个。',
      address: '监听地址',
      addressAuto: '留空则使用第一个非回环地址，填 0.0.0.0 监听所有网卡；也可以填下面检测到的地址。',
      port: '端口',
      portHint: '1 到 65535，不能与 GUI 的端口相同。',
      sessionDays: '免密天数',
      sessionDaysHint: '一次通过后多少天内不用再输密码。',
      requirePassword: '需要密码',
      requirePasswordHint: '入口要求输一次密码；不填密码就由宿主随机生成一个。',
      passwordOpen: '密码已关闭：同一网络内任何人都能直接打开这个 GUI，只在信任的网络里这样用。',
      password: '访问密码',
      passwordHint: '至少 4 位。留空则保持不变。',
      passwordGenerateHint: '至少 4 位；留空则由宿主随机生成一个。',
      passwordTooShort: '至少 4 位才能保存。',
      passwordSet: '已设置',
      passwordUnset: '未设置',
      generatedPassword: '本次生成的密码',
      generatedPasswordHint: '宿主只保存它的 scrypt 哈希，重启后不再显示；请现在复制，或直接改成自己的密码。',
      copy: '复制',
      copied: '已复制',
      copyFailed: '复制失败，请手动选中密码。',
      running: '正在监听',
      stopped: '未启动',
      upstream: '转发到',
      save: '保存',
      saving: '保存中…',
      saveFailed: '保存失败',
      readOnly: '当前设置不可改。',
      unavailable: '正在读取设置…',
      loadFailed: '读取设置失败',
      addressPick: '自动',
      addressInvalid: '需要是 IPv4 地址',
      portInvalid: '需要 1 到 65535 的整数',
      sessionDaysInvalid: '需要 1 到 365 的整数',
    }

    /** English copy. */
    const en = {
      section: 'Access',
      intro: 'Access this Web GUI from your LAN. On the same Wi-Fi, a phone or another computer opens the entry URL below and types the password once; the login then redirects with the launch token and lasts the number of days set here. The password is on by default, and a fresh entry starts with a generated one.',
      address: 'Listen address',
      addressAuto: 'Leave empty to serve the first non-loopback address, 0.0.0.0 to serve every interface, or pick one detected below.',
      port: 'Port',
      portHint: '1 to 65535, different from the GUI port.',
      sessionDays: 'Session days',
      sessionDaysHint: 'How long one passed login lasts.',
      requirePassword: 'Require a password',
      requirePasswordHint: 'The entry asks for the password once; leave the field empty and the Host generates one.',
      passwordOpen: 'The password is off: anyone who can reach this network opens the GUI directly. Use this only on a network you trust.',
      password: 'Access password',
      passwordHint: 'At least 4 characters. Leave empty to keep the current one.',
      passwordGenerateHint: 'At least 4 characters, or empty to let the Host generate one.',
      passwordTooShort: 'At least 4 characters to save.',
      passwordSet: 'Set',
      passwordUnset: 'Not set',
      generatedPassword: 'Generated password',
      generatedPasswordHint: 'The Host keeps only its scrypt hash and cannot show it again after a restart. Copy it now, or replace it with your own.',
      copy: 'Copy',
      copied: 'Copied',
      copyFailed: 'Could not copy; select the password by hand.',
      running: 'Listening on',
      stopped: 'Not running',
      upstream: 'Forwards to',
      save: 'Save',
      saving: 'Saving…',
      saveFailed: 'Save failed',
      readOnly: 'These settings are read-only here.',
      unavailable: 'Loading settings…',
      loadFailed: 'Cannot read the settings',
      addressPick: 'Auto',
      addressInvalid: 'Must be an IPv4 address',
      portInvalid: 'Must be an integer between 1 and 65535',
      sessionDaysInvalid: 'Must be an integer between 1 and 365',
    }

    /**
     * Copy the primitives do not render for us, using the same tokens. The
     * switch row repeats the built-in field metrics (`_field`: 12px 0 padding
     * and a 6px gap, `_label`: 13px/500, `_hint`: 12px tertiary) because no
     * switch field ships with them yet.
     */
    const styles = {
      root: { display: 'flex', flexDirection: 'column', gap: 16, padding: '4px 2px', maxWidth: 720 },
      intro: { margin: 0, fontSize: 14, lineHeight: '22px', color: 'var(--dsw-alias-label-tertiary, #6b7280)' },
      state: {
        margin: 0, fontSize: 13, lineHeight: '20px',
        color: 'var(--dsw-alias-label-secondary, #6b7280)',
      },
      mono: { fontFamily: 'var(--dsw-font-markdown-code-font-family, ui-monospace, Menlo, monospace)' },
      error: { margin: 0, fontSize: 13, lineHeight: '20px', color: 'var(--dsw-alias-state-error-primary, #dc2626)' },
      field: { display: 'flex', flexDirection: 'column', gap: 6, padding: '12px 0' },
      head: { display: 'flex', alignItems: 'center', gap: 8 },
      label: {
        flex: 1, minWidth: 0, fontSize: 13, fontWeight: 500, lineHeight: 1.5,
        color: 'var(--dsw-alias-label-primary, #111827)',
      },
      hint: { margin: 0, fontSize: 12, lineHeight: 1.5, color: 'var(--dsw-alias-label-tertiary, #6b7280)' },
      warn: { margin: 0, fontSize: 12, lineHeight: 1.5, color: 'var(--dsw-alias-state-warn-primary, #b45309)' },
      generated: { display: 'flex', flexDirection: 'column', gap: 6, padding: '0 0 12px' },
      secret: {
        display: 'block', margin: 0, padding: '8px 12px', borderRadius: 8, boxSizing: 'border-box',
        border: '.5px solid var(--dsw-alias-border-l4, #00000029)',
        background: 'var(--dsw-alias-bg-layer-3, #f3f4f6)',
        color: 'var(--dsw-alias-label-primary, #111827)',
        fontFamily: 'var(--dsw-font-markdown-code-font-family, ui-monospace, Menlo, monospace)',
        fontSize: 14, lineHeight: '20px', letterSpacing: '.06em',
        userSelect: 'all', wordBreak: 'break-all',
      },
      picks: { display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: -8 },
      picked: { background: 'var(--dsw-alias-interactive-bg-active, #2631481a)' },
    }

    /** Send one request to the Host route and unwrap its envelope. */
    async function call(endpoint, payload = {}) {
      const response = await fetch(new URL(RPC_PATH, document.baseURI).href, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ endpoint, ...payload }),
      })
      if (response.ok !== true) throw new Error(`HTTP ${response.status}`)
      const body = await response.json()
      if (body.ok !== true) throw new Error(body.error?.message ?? 'request failed')
      return body.value
    }

    /** Whether a string is a concrete IPv4 literal. */
    function isIpv4(value) {
      const parts = value.split('.')
      if (parts.length !== 4) return false
      return parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)
    }

    /**
     * Copy text from a click. The async clipboard API needs a secure context, so
     * a Settings page opened over plain HTTP on the LAN falls back to the old
     * selection command rather than telling the user to select by hand.
     */
    async function copyText(text) {
      if (typeof navigator.clipboard?.writeText === 'function') {
        await navigator.clipboard.writeText(text)
        return
      }
      const area = document.createElement('textarea')
      area.value = text
      area.style.position = 'fixed'
      area.style.top = '-1000px'
      area.style.opacity = '0'
      document.body.appendChild(area)
      area.select()
      try {
        if (document.execCommand('copy') !== true) throw new Error('copy failed')
      } finally {
        area.remove()
      }
    }

    /** The Settings section: one form over the entry and its password. */
    function AccessGatewaySettings({ t }) {
      const [view, setView] = useState(null)
      const [viewError, setViewError] = useState('')
      const [form, setForm] = useState({ bind: '', port: '3081', sessionDays: '30' })
      const [password, setPassword] = useState('')
      const [requirePassword, setRequirePassword] = useState(false)
      const [busy, setBusy] = useState(false)
      const [failed, setFailed] = useState(false)
      const [copied, setCopied] = useState('')

      const adopt = useCallback((value) => {
        setView(value)
        setForm({
          bind: value.settings.bind,
          port: String(value.settings.port),
          sessionDays: String(value.settings.sessionDays),
        })
        setPassword('')
        setRequirePassword(value.settings.passwordEnabled === true)
        setCopied('')
      }, [])

      useEffect(() => {
        let live = true
        call('get')
          .then((value) => { if (live) adopt(value) })
          .catch((error) => { if (live) setViewError(error.message) })
        return () => { live = false }
      }, [adopt])

      const discard = useCallback(() => {
        if (view === null) return
        setForm({
          bind: view.settings.bind,
          port: String(view.settings.port),
          sessionDays: String(view.settings.sessionDays),
        })
        setPassword('')
        setRequirePassword(view.settings.passwordEnabled === true)
        setFailed(false)
        setCopied('')
      }, [view])

      const bindInvalid = form.bind !== '' && isIpv4(form.bind) !== true
      const portValue = Number(form.port)
      const portInvalid = /^\d+$/.test(form.port) !== true || portValue < 1 || portValue > 65535
      const daysValue = Number(form.sessionDays)
      const daysInvalid = /^\d+$/.test(form.sessionDays) !== true || daysValue < 1 || daysValue > 365
      const dirty = view !== null && (
        form.bind !== view.settings.bind
        || portValue !== view.settings.port
        || daysValue !== view.settings.sessionDays
        || password !== ''
        || requirePassword !== (view.settings.passwordEnabled === true)
      )
      const passwordStored = view?.passwordSet === true
      const passwordInvalid = requirePassword === true && password !== '' && password.length < 4
      // Switching on with an empty field asks the Host to generate one, so a
      // missing password is no longer a reason to block the save.
      const invalid = bindInvalid || portInvalid || daysInvalid || passwordInvalid
      // Shown only while the user has not typed a replacement of their own.
      const generated = requirePassword === true && password === '' ? (view?.generatedPassword ?? '') : ''

      const copyGenerated = async () => {
        if (generated === '') return
        try {
          await copyText(generated)
          setCopied('done')
        } catch {
          setCopied('failed')
        }
      }

      const save = async () => {
        setBusy(true)
        setFailed(false)
        try {
          const value = await call('save', {
            settings: {
              bind: form.bind.trim(),
              port: portValue,
              sessionDays: daysValue,
              passwordEnabled: requirePassword,
            },
            // `null` switches the password off, so the entry opens for anyone on
            // the network; an empty string keeps the current password.
            password: requirePassword ? password : null,
          })
          adopt(value)
        } catch {
          setFailed(true)
        } finally {
          setBusy(false)
        }
      }

      const effective = view?.effective
      const candidates = view?.candidates ?? []
      const pick = (value) => setForm((current) => ({ ...current, bind: value }))
      const choice = (picked) => ({
        variant: 'outline',
        size: 'sm',
        disabled: busy,
        'aria-pressed': picked,
        style: picked ? styles.picked : undefined,
      })
      const stateText = effective === undefined
        ? ''
        : effective.running
          ? `${t('running')} ${effective.urls.length === 0 ? effective.url : effective.urls.join(' · ')}`
          : `${t('stopped')}${effective.error === '' ? '' : `: ${effective.error}`}`

      return h('div', { style: styles.root },
        h('p', { style: styles.intro }, t('intro')),
        viewError === ''
          ? null
          : h('p', { style: styles.error }, `${t('loadFailed')}: ${viewError}`),
        effective === undefined
          ? null
          : h('p', { style: styles.state },
            stateText,
            h('span', { style: styles.mono }, ` · ${t('upstream')} 127.0.0.1:${effective.upstreamPort}`)),
        h(SettingsForm, {
          state: {
            available: view !== null || viewError !== '',
            writable: true,
            dirty,
            invalid,
            saving: busy,
            failed,
          },
          labels: {
            save: t('save'),
            saving: t('saving'),
            saveFailed: t('saveFailed'),
            readOnly: t('readOnly'),
            unavailable: viewError === '' ? t('unavailable') : t('loadFailed'),
          },
          onSave: save,
          onDiscard: discard,
        },
          h(SettingsValueField, {
            id: 'access-gateway-bind',
            label: t('address'),
            hint: t('addressAuto'),
            text: form.bind,
            disabled: busy,
            invalid: bindInvalid,
            invalidLabel: t('addressInvalid'),
            onEdit: (text) => setForm((current) => ({ ...current, bind: text })),
          }),
          candidates.length === 0
            ? null
            : h('div', { style: styles.picks },
              h(Button, {
                key: 'auto',
                ...choice(form.bind === ''),
                onClick: () => pick(''),
              }, t('addressPick')),
              candidates.map((candidate) => h(Button, {
                key: candidate.address,
                ...choice(form.bind === candidate.address),
                onClick: () => pick(candidate.address),
              }, `${candidate.label} ${candidate.address}`))),
          h(SettingsValueField, {
            id: 'access-gateway-port',
            label: t('port'),
            hint: t('portHint'),
            text: form.port,
            numeric: true,
            disabled: busy,
            invalid: portInvalid,
            invalidLabel: t('portInvalid'),
            onEdit: (text) => setForm((current) => ({ ...current, port: text })),
          }),
          h(SettingsValueField, {
            id: 'access-gateway-session-days',
            label: t('sessionDays'),
            hint: t('sessionDaysHint'),
            text: form.sessionDays,
            numeric: true,
            disabled: busy,
            invalid: daysInvalid,
            invalidLabel: t('sessionDaysInvalid'),
            onEdit: (text) => setForm((current) => ({ ...current, sessionDays: text })),
          }),
          h('div', { style: styles.field },
            h('div', { style: styles.head },
              h('span', { style: styles.label }, t('requirePassword')),
              h(Switch, {
                checked: requirePassword,
                onChange: (next) => {
                  setRequirePassword(next)
                  if (next !== true) setPassword('')
                  setCopied('')
                },
                label: t('requirePassword'),
                disabled: busy,
              })),
            h('p', { style: requirePassword ? styles.hint : styles.warn },
              requirePassword ? t('requirePasswordHint') : t('passwordOpen'))),
          generated === ''
            ? null
            : h('div', { style: styles.generated },
              h('div', { style: styles.head },
                h('span', { style: styles.label }, t('generatedPassword')),
                h(Button, {
                  variant: 'outline',
                  size: 'sm',
                  disabled: busy,
                  onClick: () => { void copyGenerated() },
                }, copied === 'done' ? t('copied') : t('copy'))),
              h('code', { style: styles.secret }, generated),
              h('p', { style: styles.hint }, t('generatedPasswordHint')),
              copied === 'failed' ? h('p', { style: styles.warn }, t('copyFailed')) : null),
          requirePassword
            ? h(SettingsSecretField, {
              id: 'access-gateway-password',
              label: t('password'),
              hint: passwordInvalid
                ? t('passwordTooShort')
                : (passwordStored ? t('passwordHint') : t('passwordGenerateHint')),
              stateLabel: passwordStored ? t('passwordSet') : t('passwordUnset'),
              configured: passwordStored,
              text: password,
              disabled: busy,
              onEdit: (text) => setPassword(text),
            })
            : null),
      )
    }

    return {
      inject: ['slots', 'locale'],
      /**
       * Register the copy and the Settings section.
       * @param ctx - Client root Context with slots and locale.
       */
      apply(ctx) {
        const translate = ctx.locale.bind(NS)
        ctx.effect(() => ctx.locale.register(NS, { zh, en }), 'dsh-access-gateway: copy')
        ctx.effect(() => ctx.slots.inject('settings.section', () => ctx.slots.register({
          name: 'settings.section',
          id: 'dsh-access-gateway',
          order: 2,
          label: () => translate('section'),
          inject: () => ({ t: translate }),
        }, AccessGatewaySettings)), 'dsh-access-gateway: settings section')
      },
    }
  },
})
