<script setup lang="ts">
import { computed, inject, ref } from "vue";
import { PhArrowRight as ArrowRight, PhFingerprint as Fingerprint, PhKey as Key, PhShieldCheck as ShieldCheck } from "@phosphor-icons/vue";
import type { APIClient } from "../api";
import { APIProblem } from "../api";
import { sessionStore, type ViewerProjection } from "../store";

const api=inject<APIClient>("api")!;
type Mode="login"|"totp"|"claim";
const mode=ref<Mode>(api.available("identity.installation.claim")&&!api.available("identity.session.login")?"claim":"login");
const username=ref("");const email=ref("");const password=ref("");const totp=ref("");const claimToken=ref("");const displayName=ref("");const loading=ref(false);const error=ref("");const challengeID=ref("");
const heading=computed(()=>mode.value==="claim"?"Claim this installation":mode.value==="totp"?"Complete verification":"Sign in to the node");
const submitLabel=computed(()=>mode.value==="claim"?"Create installation owner":mode.value==="totp"?"Verify code":"Continue securely");

async function submit():Promise<void>{loading.value=true;error.value="";try{
  if(mode.value==="claim"){
    await api.invoke("identity.installation.claim",{payload:{claim_token:claimToken.value,display_name:displayName.value,email:email.value,password:password.value},expectedGeneration:1});
    mode.value="login";password.value="";sessionStore.notify({tone:"healthy",title:"Installation claimed",body:"Sign in with the owner account you just created."});return;
  }
  if(mode.value==="totp"){
    const response=await api.invoke<{viewer:ViewerProjection}>("identity.session.mfa_totp",{payload:{challenge_id:challengeID.value,code:totp.value}});setViewer(response.result.viewer);return;
  }
  const response=await api.invoke<{mfa_required?:boolean;challenge_id?:string;viewer?:ViewerProjection}>("identity.session.login",{payload:{username:username.value,password:password.value}});
  password.value="";
  if(response.result.mfa_required&&response.result.challenge_id){challengeID.value=response.result.challenge_id;mode.value="totp";return}
  if(response.result.viewer){setViewer(response.result.viewer);return}
  throw new Error("The login response was incomplete.");
}catch(cause){error.value=cause instanceof APIProblem?cause.problem.detail||cause.problem.title:cause instanceof Error?cause.message:"Authentication failed."}finally{loading.value=false}}
function setViewer(viewer:ViewerProjection):void{sessionStore.setProjection(viewer)}
async function passkey():Promise<void>{error.value="";if(!window.PublicKeyCredential){error.value="Passkeys are not supported by this browser.";return}loading.value=true;try{const begin=await api.invoke<{challenge_id:string;public_key:Record<string,unknown>}>("identity.session.webauthn.begin",{payload:{username:username.value}});const credential=await navigator.credentials.get({publicKey:decodePublicKey(begin.result.public_key)}) as PublicKeyCredential|null;if(!credential)throw new Error("Passkey verification was cancelled.");const response=await api.invoke<{viewer:ViewerProjection}>("identity.session.webauthn.finish",{payload:{challenge_id:begin.result.challenge_id,response:serializeCredential(credential)}});setViewer(response.result.viewer)}catch(cause){error.value=cause instanceof Error?cause.message:"Passkey verification failed."}finally{loading.value=false}}
function serializeCredential(credential:PublicKeyCredential):Record<string,unknown>{const response=credential.response as AuthenticatorAssertionResponse;return{id:credential.id,type:credential.type,raw_id:base64url(credential.rawId),response:{client_data_json:base64url(response.clientDataJSON),authenticator_data:base64url(response.authenticatorData),signature:base64url(response.signature),user_handle:response.userHandle?base64url(response.userHandle):null}}}
function base64url(buffer:ArrayBuffer):string{let binary="";new Uint8Array(buffer).forEach((byte)=>binary+=String.fromCharCode(byte));return btoa(binary).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"")}
function decodePublicKey(value:Record<string,unknown>):PublicKeyCredentialRequestOptions{const decoded={...value} as Record<string,unknown>;if(typeof decoded.challenge==="string")decoded.challenge=fromBase64url(decoded.challenge);if(Array.isArray(decoded.allowCredentials))decoded.allowCredentials=decoded.allowCredentials.map((entry)=>{const item={...(entry as Record<string,unknown>)};if(typeof item.id==="string")item.id=fromBase64url(item.id);return item});return decoded as unknown as PublicKeyCredentialRequestOptions}
function fromBase64url(value:string):ArrayBuffer{const padded=value.replace(/-/g,"+").replace(/_/g,"/")+"=".repeat((4-value.length%4)%4);const binary=atob(padded);const bytes=new Uint8Array(binary.length);for(let index=0;index<binary.length;index++)bytes[index]=binary.charCodeAt(index);return bytes.buffer}
</script>

<template>
  <main class="auth-stage">
    <section class="auth-context" aria-hidden="true">
      <div class="auth-brand"><span class="auth-logo"><i></i><i></i></span><strong>CyberPanel</strong></div>
      <div class="context-copy"><p class="system-label">LOCAL AUTHORITY / STANDALONE READY</p><h1>Infrastructure control without surrendering the server.</h1><p>Every change is admitted locally, reconciled durably, and bounded by the authority you grant.</p></div>
      <div class="context-grid"><div><ShieldCheck :size="21"/><span><strong>Closed privileged boundary</strong><small>No browser root shell or arbitrary command executor.</small></span></div><div><Fingerprint :size="21"/><span><strong>Independent assurance</strong><small>Step-up confirmation for high-risk commits.</small></span></div><div><Key :size="21"/><span><strong>Purpose-bound secrets</strong><small>Credentials never live in application environment files.</small></span></div></div>
      <div class="context-foot"><span></span>Local services continue when the central plane is offline.</div>
    </section>
    <section class="auth-panel">
      <form class="auth-form" @submit.prevent="submit">
        <header><p>{{mode==='claim'?'ONE-TIME LOCAL CEREMONY':'AUTHORIZED ACCESS'}}</p><h2>{{heading}}</h2><span v-if="mode==='totp'">Enter the current code from your enrolled authenticator.</span><span v-else-if="mode==='claim'">The claim token is accepted once and never stored.</span><span v-else>Use your local account or a phishing-resistant passkey.</span></header>
        <div v-if="mode==='claim'" class="field"><label for="display-name">Display name</label><input id="display-name" v-model="displayName" class="input" autocomplete="name" required/></div>
        <div v-if="mode==='claim'" class="field"><label for="claim-token">Installation claim token</label><input id="claim-token" v-model="claimToken" class="input mono" type="password" autocomplete="one-time-code" required/><p class="field-help">Read from the local installation console.</p></div>
        <div v-if="mode==='claim'" class="field"><label for="email">Email address</label><input id="email" v-model="email" class="input" type="email" autocomplete="email" required/></div>
        <div v-if="mode==='login'" class="field"><label for="username">Username</label><input id="username" v-model="username" class="input" autocomplete="username" required/></div>
        <div v-if="mode!=='totp'" class="field"><label for="password">Password</label><input id="password" v-model="password" class="input" type="password" :autocomplete="mode==='claim'?'new-password':'current-password'" minlength="12" required/></div>
        <div v-else class="field"><label for="totp">Verification code</label><input id="totp" v-model="totp" class="input mono code-input" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6,8}" maxlength="8" required/></div>
        <div v-if="error" class="auth-error" role="alert">{{error}}</div>
        <button class="button button-primary auth-submit" type="submit" :disabled="loading"><span>{{loading?'Verifying…':submitLabel}}</span><ArrowRight :size="17"/></button>
        <button v-if="mode==='login'&&api.available('identity.session.webauthn.begin')" class="button passkey" type="button" :disabled="loading" @click="passkey"><Fingerprint :size="18"/>Use a passkey</button>
        <button v-if="mode==='totp'" class="text-button" type="button" @click="mode='login';totp='';error=''">Return to sign in</button>
      </form>
    </section>
  </main>
</template>

<style scoped>
.auth-stage{min-height:100dvh;display:grid;grid-template-columns:minmax(420px,1.16fr) minmax(420px,.84fr);background:var(--bg)}.auth-context{position:relative;overflow:hidden;padding:44px clamp(38px,6vw,96px);display:flex;flex-direction:column;justify-content:space-between;border-right:1px solid var(--border);background:radial-gradient(circle at 17% 80%,rgba(37,208,216,.09),transparent 29%),linear-gradient(145deg,var(--bg-raised),var(--bg))}.auth-context::after{content:"";position:absolute;inset:0;pointer-events:none;opacity:.23;background-image:linear-gradient(var(--border) 1px,transparent 1px),linear-gradient(90deg,var(--border) 1px,transparent 1px);background-size:68px 68px;mask-image:linear-gradient(to bottom,transparent,black 25%,black 80%,transparent)}.auth-brand,.context-copy,.context-grid,.context-foot{position:relative;z-index:1}.auth-brand{display:flex;align-items:center;gap:12px;font-size:17px}.auth-logo{width:38px;height:38px;border:1px solid var(--border-strong);border-radius:7px;position:relative;display:grid;place-items:center;background:var(--surface)}.auth-logo i{position:absolute;width:4px;height:20px;background:var(--accent);transform:skew(-21deg)}.auth-logo i:first-child{height:13px;margin-left:-10px}.auth-logo i:last-child{margin-left:9px}.context-copy{max-width:660px;margin:12vh 0 8vh}.system-label{font:10px/1 "Panel Mono",monospace;letter-spacing:.14em;color:var(--accent);margin:0 0 20px}.context-copy h1{font-size:clamp(42px,5.2vw,76px);letter-spacing:-.055em;line-height:.94;margin:0;max-width:11ch}.context-copy>p:last-child{max-width:49ch;color:var(--muted);font-size:16px;line-height:1.65;margin:26px 0 0}.context-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;background:var(--border);border:1px solid var(--border)}.context-grid>div{display:flex;gap:11px;padding:17px;background:var(--bg-raised)}.context-grid svg{color:var(--accent);flex:0 0 auto}.context-grid span{display:grid;gap:5px}.context-grid strong{font-size:12px}.context-grid small{color:var(--subtle);line-height:1.45}.context-foot{display:flex;align-items:center;gap:9px;margin-top:30px;color:var(--subtle);font:11px/1.4 "Panel Mono",monospace}.context-foot span{width:7px;height:7px;border-radius:50%;background:var(--healthy)}.auth-panel{display:grid;place-items:center;padding:40px;background:var(--bg-raised)}.auth-form{width:min(390px,100%);display:grid;gap:19px}.auth-form header{display:grid;gap:10px;margin-bottom:10px}.auth-form header p{color:var(--accent);font:10px/1 "Panel Mono",monospace;letter-spacing:.14em;margin:0}.auth-form header h2{font-size:31px;line-height:1.1;letter-spacing:-.04em;margin:0}.auth-form header span{color:var(--muted);max-width:42ch}.auth-error{border-left:3px solid var(--critical);background:color-mix(in srgb,var(--critical),transparent 90%);color:var(--critical);padding:11px 13px;border-radius:4px;font-size:13px}.auth-submit,.passkey{width:100%;min-height:44px}.auth-submit span{flex:1}.passkey{background:transparent}.text-button{border:0;background:transparent;color:var(--accent);cursor:pointer;padding:7px}.code-input{font-size:24px;letter-spacing:.25em;text-align:center}.field-help{color:var(--subtle)}
@media(max-width:980px){.auth-stage{grid-template-columns:1fr}.auth-context{display:none}.auth-panel{min-height:100dvh}}
</style>
