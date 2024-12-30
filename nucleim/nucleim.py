from .__version__ import __version__
import subprocess
import json
import os
from urllib.parse import urlparse
from b_hunters.bhunter import BHunters
from karton.core import Task
import tempfile
import requests
import re
from bson.objectid import ObjectId

class nucleim(BHunters):
    """
    Nuclei scanner developed by Bormaa
    """

    identity = "B-Hunters-Nuclei"
    version = __version__
    persistent = True
    scan_type=os.getenv("scan_type","Full")
    if scan_type=="Full":
        
        filters = [
            {
                "type": "subdomain", "stage": "new"
            },
            {
                "type": "paths", "stage": "scan"
            }
        ]
    else:
        filters = [
            {
                "type": "subdomain", "stage": "new"
            }
        ]
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
    def nucleiscansingle(self,url):
        try:
            filename=self.generate_random_filename()
            p1=subprocess.Popen(["nuclei","-es","info","-t","/app/templates","-etags","ssl","-target", url,"-o",filename], stdout=subprocess.PIPE)
            data=""
            result=""
            try:
                output, _ = p1.communicate(timeout=3600)  # 60 minutes timeout
            except subprocess.TimeoutExpired:
                p1.kill()
                try:
                    output, _ = p1.communicate(timeout=5)  # Give it a few seconds to fully terminate
                except subprocess.TimeoutExpired:
                    self.log.error("Force-killing Nuclei process after failed kill attempt.")
                    p1.terminate()  # Fallback to terminate if kill is insufficient
            if os.path.exists(filename) and os.path.getsize(filename) > 0:  # Check if file exists and is not empty
                with open(filename, 'r') as file:
                    try:
                        data = file.read()
                        # print("data is ",data)
                    except Exception as e:
                        print("Error:",e)
                        result=""
                if data!="":
                    dataarr=data.split("\n")
                    result=dataarr
                os.remove(filename)
        except Exception as e:
            self.log.error(e)
            raise Exception(e)
        return result
    def nucleiscanfile(self,data):
        
        outputfile=self.generate_random_filename()+".txt"
        filename=self.generate_random_filename()+".txt"
        with open(filename, 'wb') as file:
            # for item in data:
            file.write(data)
            
        p1 = subprocess.Popen(["cat", filename], stdout=subprocess.PIPE)


        # Command 3: grep -v 'png\|jpg\|css\|js\|gif\|txt'
        p3 = subprocess.Popen(["grep", "-v", "png\|jpg\|css\|js\|gif\|txt"], stdin=p1.stdout, stdout=subprocess.PIPE)
        p1.stdout.close()

        # Command 4: grep '='
        p4 = subprocess.Popen(["grep", "="], stdin=p3.stdout, stdout=subprocess.PIPE)
        p3.stdout.close()

        # Command 5: uro
        p5 = subprocess.Popen(["uro","--filter","hasparams"], stdin=p4.stdout, stdout=subprocess.PIPE)
        p4.stdout.close()
        newlinks=self.checklinksexist(self.subdomain,p5.stdout.read().decode("utf-8"))
        # Command 7: dalfox pipe --deep-domxss --multicast --blind 
        if newlinks==[]:
            return []
        p6=subprocess.Popen(["nuclei","-t","/app/templates","-dast","-rl","20","-o",outputfile], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        p6.stdin.write('\n'.join(newlinks).encode())
        p5.stdout.close()

        data=""
        result=""
        try:
            output, _ = p6.communicate(timeout=7200)  # 120 minutes timeout
        except subprocess.TimeoutExpired:
            p6.kill()
            try:
                output, _ = p6.communicate(timeout=5)  # Give it a few seconds to fully terminate
            except subprocess.TimeoutExpired:
                self.log.error("Force-killing Nuclei process after failed kill attempt.")
                p6.terminate()  # Fallback to terminate if kill is insufficient
        if os.path.exists(outputfile) and os.path.getsize(outputfile) > 0:  # Check if file exists and is not empty
            with open(outputfile, 'r') as file:
                try:
                    data = file.read()
                    # print("data is ",data)
                except Exception as e:
                    print("Error:",e)
                    result=""
            if data!="":
                dataarr=data.split("\n")
                result=dataarr
            os.remove(filename)
            os.remove(outputfile)
        
        return result
                
    def scan(self,url):
        if self.source == "subrecon":
            
            result=self.nucleiscansingle(url)
        else:
            data=self.backend.download_object("bhunters",f"{self.source}_"+self.scanid+"_"+self.encode_filename(url))
            result=self.nucleiscanfile(data)

        return result
        
        
    def process(self, task: Task) -> None:
        source = task.payload["source"]
        self.source=source
        self.scanid=task.payload_persistent["scan_id"]
        report_id=task.payload_persistent["report_id"]

        subdomain = task.payload["subdomain"]
        subdomain = re.sub(r'^https?://', '', subdomain)
        subdomain = subdomain.rstrip('/')
        self.subdomain=subdomain
        url = task.payload["data"]
        self.log.info("Starting processing new url " +url)
        self.update_task_status(subdomain,"Started")
        url = re.sub(r'^https?://', '', url)
        url = url.rstrip('/')
        try:

            result=self.scan(url)
            self.waitformongo()
            db = self.db
            resarr=[]
            for i in result:
                if i != "":
                    resarr.append(i)
            
            if resarr !=[] and len(resarr)>0:
                resultdata = "\n".join(map(lambda x: str(x), resarr)).encode()
                collection = db["reports"]
                collection.update_one({"_id":ObjectId(report_id)}, {"$push": {f"Vulns.Nuclei": {"$each": resarr}}}, upsert=True)

                self.send_discord_webhook(f"New Nuclei Vulnerability Found for {url} ",resultdata.decode('utf-8'),channel="main")
            self.update_task_status(subdomain,"Finished")



        except Exception as e:
            self.log.error(e)
            self.update_task_status(subdomain,"Failed")