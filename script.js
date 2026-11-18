const $ = (id) => document.getElementById(id);
const state = {
  packets: 1284, allowed: 1102, blocked: 182, processed: 0, simAllowed: 0, simBlocked: 0,
  rules: [
    {ip:"192.168.1.105",port:"22",action:"Block",status:"Active"},
    {ip:"10.0.0.24",port:"443",action:"Allow",status:"Active"},
    {ip:"203.0.113.18",port:"*",action:"Block",status:"Active"},
    {ip:"192.168.1.1",port:"80",action:"Allow",status:"Active"}
  ],
  blacklist: [
    {ip:"203.0.113.18",reason:"Repeated suspicious requests",date:"18 Nov 2026"},
    {ip:"198.51.100.42",reason:"Port scanning activity",date:"18 Nov 2026"}
  ],
  logs: [
    {time:"08:42:16",ip:"192.168.1.105",event:"SSH connection attempt",port:"22",decision:"Blocked"},
    {time:"08:41:53",ip:"10.0.0.24",event:"HTTPS request",port:"443",decision:"Allowed"},
    {time:"08:40:29",ip:"203.0.113.18",event:"Suspicious access",port:"8080",decision:"Blocked"},
    {time:"08:39:04",ip:"192.168.1.1",event:"HTTP request",port:"80",decision:"Allowed"},
    {time:"08:37:41",ip:"198.51.100.42",event:"Port scan detected",port:"21",decision:"Blocked"}
  ],
  running:false
};
const randomIP = () => `${10+Math.floor(Math.random()*220)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${2+Math.floor(Math.random()*250)}`;
const timeNow = () => new Date().toLocaleTimeString("id-ID",{hour12:false});
function toast(message){const el=$("toast");el.textContent=message;el.classList.add("show");setTimeout(()=>el.classList.remove("show"),2300)}
function decisionClass(v){return v==="Allowed"?"allowed":"blocked"}
function renderLogs(){
  const rows=state.logs.map(l=>`<tr><td>${l.time}</td><td class="ip-cell">${l.ip}</td><td>${l.event}</td><td>${l.port}</td><td><span class="decision ${decisionClass(l.decision)}">${l.decision}</span></td></tr>`).join("");
  $("recentRows").innerHTML=rows.slice(0,5)||'<tr><td colspan="5" class="empty-state">Belum ada aktivitas.</td></tr>';
  const q=($("logSearch")?.value||"").toLowerCase();
  const filtered=state.logs.filter(l=>[l.ip,l.event,l.port,l.decision].join(" ").toLowerCase().includes(q));
  $("logsRows").innerHTML=filtered.map(l=>`<tr><td>${l.time}</td><td class="ip-cell">${l.ip}</td><td>${l.event}</td><td>${l.port}</td><td><span class="decision ${decisionClass(l.decision)}">${l.decision}</span></td></tr>`).join("")||'<tr><td colspan="5" class="empty-state">Tidak ada log yang cocok.</td></tr>';
  $("logSubtitle").textContent=`Menampilkan ${filtered.length} dari ${state.logs.length} catatan aktivitas`;
}
function renderRules(){
  $("rulesRows").innerHTML=state.rules.map((r,i)=>`<tr><td class="ip-cell">${r.ip}</td><td>${r.port}</td><td><span class="decision ${r.action==="Allow"?"allowed":"blocked"}">${r.action}</span></td><td><span class="green-text">● ${r.status}</span></td><td><button class="action-btn" onclick="removeRule(${i})">Remove</button></td></tr>`).join("")||'<tr><td colspan="5" class="empty-state">Belum ada aturan firewall.</td></tr>';
  $("ruleCount").textContent=String(state.rules.length).padStart(2,"0");$("ruleTotal").textContent=`${state.rules.length} RULES`;
}
function renderBlacklist(){
  $("blackRows").innerHTML=state.blacklist.map((b,i)=>`<tr><td class="ip-cell">${b.ip}</td><td>${b.reason}</td><td>${b.date}</td><td><button class="action-btn" onclick="removeBlack(${i})">Unblock</button></td></tr>`).join("")||'<tr><td colspan="4" class="empty-state">Blacklist masih kosong.</td></tr>';
  $("blackTotal").textContent=`${state.blacklist.length} BLOCKED`;
}
function renderStats(){
  $("totalPackets").textContent=state.packets.toLocaleString("en-US");$("allowedCount").textContent=state.allowed.toLocaleString("en-US");$("blockedCount").textContent=state.blocked.toLocaleString("en-US");$("threatTotal").textContent=state.blocked.toLocaleString("en-US");
  $("simProcessed").textContent=state.processed;$("simAllowed").textContent=state.simAllowed;$("simBlocked").textContent=state.simBlocked;
}
function addLog(ip,event,port,decision){state.logs.unshift({time:timeNow(),ip,event,port,decision});if(state.logs.length>100)state.logs.pop();renderLogs()}
function removeRule(i){state.rules.splice(i,1);renderRules();toast("Aturan firewall dihapus.")}
function removeBlack(i){state.blacklist.splice(i,1);renderBlacklist();toast("IP dihapus dari blacklist.")}
window.removeRule=removeRule;window.removeBlack=removeBlack;
$("ruleForm").addEventListener("submit",e=>{e.preventDefault();const ip=$("ruleIp").value.trim(),port=$("rulePort").value.trim(),action=$("ruleAction").value;if(ip&&!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)){toast("Format IP address belum valid.");return}if(port&&(Number(port)<1||Number(port)>65535)){toast("Port harus berada di antara 1–65535.");return}state.rules.push({ip:ip||"Any IP",port:port||"*",action,status:"Active"});renderRules();e.target.reset();toast("Firewall rule berhasil ditambahkan.")});
$("blacklistForm").addEventListener("submit",e=>{e.preventDefault();const ip=$("blackIp").value.trim(),reason=$("blackReason").value.trim();if(!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)){toast("Masukkan format IP address yang valid.");return}if(state.blacklist.some(b=>b.ip===ip)){toast("IP tersebut sudah ada di blacklist.");return}state.blacklist.unshift({ip,reason,date:new Date().toLocaleDateString("id-ID",{day:"2-digit",month:"short",year:"numeric"})});state.rules.push({ip,port:"*",action:"Block",status:"Active"});renderBlacklist();renderRules();e.target.reset();toast("IP berhasil dimasukkan ke blacklist.")});
function simulateOne(){
  const ip=randomIP(),port=[22,80,443,8080,21,3306,53][Math.floor(Math.random()*7)];
  const matching=state.rules.find(r=>(r.ip==="Any IP"||r.ip===ip)&&(r.port==="*"||Number(r.port)===port));
  const black=state.blacklist.some(b=>b.ip===ip);
  const suspicious=port===22||port===21||Math.random()<.16;
  const blocked=black||(matching?matching.action==="Block":suspicious);
  const decision=blocked?"Blocked":"Allowed",event=blocked?(black?"Blacklisted IP detected":"Suspicious connection attempt"):"Network packet forwarded";
  state.packets++;state.processed++;if(blocked){state.blocked++;state.simBlocked++}else{state.allowed++;state.simAllowed++}
  addLog(ip,event,port,decision);renderStats();
  $("simOutput").textContent=`[${timeNow()}] ${ip}:${port} → ${decision.toUpperCase()} — ${event}`;
  if(state.processed%4===0)toast(`Paket diperiksa: ${state.processed}`);
}
let simTimer=null;
$("runSimulation").addEventListener("click",()=>{if(simTimer)return;state.running=true;simulateOne();simTimer=setInterval(simulateOne,1100);$("runSimulation").textContent="● Simulation running";toast("Simulasi traffic dimulai.")});
$("pauseSimulation").addEventListener("click",()=>{clearInterval(simTimer);simTimer=null;state.running=false;$("runSimulation").textContent="▶ Run traffic simulation";$("simOutput").textContent="Simulasi dijeda. Tekan Run untuk melanjutkan.";toast("Simulasi dijeda.")});
$("clearLogs").addEventListener("click",()=>{state.logs=[];renderLogs();toast("Semua log berhasil dihapus.")});
$("logSearch").addEventListener("input",renderLogs);
document.querySelectorAll(".nav-link").forEach(link=>link.addEventListener("click",e=>{e.preventDefault();const target=link.dataset.section;document.querySelectorAll(".page").forEach(p=>p.classList.toggle("active-page",p.id===target));document.querySelectorAll(".nav-link").forEach(a=>a.classList.toggle("active",a===link));$("pageName").textContent=link.textContent.trim();history.replaceState(null,"",`#${target}`);$("sidebar").classList.remove("open");window.scrollTo({top:0,behavior:"smooth"})}));
$("menuBtn").addEventListener("click",()=>$("sidebar").classList.toggle("open"));
$("dateNow").textContent=new Date().toLocaleDateString("id-ID",{weekday:"long",day:"2-digit",month:"long",year:"numeric"});
const initial=location.hash.slice(1);if(initial&&$(initial)){document.querySelector(`[data-section="${initial}"]`)?.click()}
renderLogs();renderRules();renderBlacklist();renderStats();
