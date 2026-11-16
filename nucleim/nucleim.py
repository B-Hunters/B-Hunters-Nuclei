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
    # The filters do not depend on the environment: a worker whose queue
    # binding changes with an environment variable has a contract that
    # cannot be reasoned about.  The worker always binds to both filters
    # and decides what to do at run time.
    filters = [
        {
            "type": "subdomain", "stage": "new"
        },
        {
            "type": "paths", "stage": "scan"
        }
    ]
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
    def header_args(self,headers):
        """The arguments that give nuclei the session headers.

        Nuclei takes them as ``-H "name: value"`` and sends them with
        every request it makes.
        """
        args=[]
        for name,value in headers.items():
            args += ["-H", f"{name}: {value}"]
        return args
    def nucleiscansingle(self,url,headers):
        try:
            filename=self.generate_random_filename()
            # The scan gives every worker a share of its time: the run is
            # bounded in the number of requests it makes, in the rate it
            # makes them and in the time it may take.
            p1=subprocess.Popen(["nuclei","-es","info","-t","/app/templates","-etags","ssl","-c","25","-timeout","10","-target", url,"-o",filename]+self.header_args(headers), stdout=subprocess.PIPE)
            data=""
            result=""
            try:
                output, _ = p1.communicate(timeout=300)  # 5 minutes timeout
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
    def nucleiscanfile(self,data,headers):
        
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
        newlinks=self.checklinksexist(self.subdomain, [link for link in p5.stdout.read().decode("utf-8") if is_on_target(self.subdomain, link)])
        # Command 7: dalfox pipe --deep-domxss --multicast --blind 
        if newlinks==[]:
            return []
        p6=subprocess.Popen(["nuclei","-t","/app/templates","-dast","-rl","150","-timeout","10","-o",outputfile]+self.header_args(headers), stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        p6.stdin.write('\n'.join(newlinks).encode())
        p5.stdout.close()

        data=""
        result=""
        try:
            output, _ = p6.communicate(timeout=300)  # 5 minutes timeout
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
                
    def url_list(self, source, url):
        """The URL list the crawler produced.

        The copy in the object store is temporary: Karton's garbage
        collector removes it once no live task refers to it, so a scanner
        that starts late finds it gone and the scan dies without looking
        at anything.  The database holds the same list, and it is what the
        scanner falls back to.
        """
        try:
            return self.backend.download_object(
                "bhunters",
                f"{source}_" + self.scanid + "_" + self.encode_filename(url),
            )
        except Exception as exc:
            self.log.error(f"the URL list is not in the bucket: {exc}")
            document = self.db["links"].find_one(
                {
                    "report_id": ObjectId(self.report_id),
                    "source": {"$regex": source, "$options": "i"},
                }
            )
            if document is None:
                raise
            links = document.get("Links") or []
            self.log.info(f"using {len(links)} link(s) from the database")
            return "\n".join(str(link) for link in links).encode()

    def checklinksexist(self, subdomain, links):
        """The links of this scanner that this scan has not checked yet.

        The shared base class in the published ``b-hunters`` package keys
        its record by host, and a host can have several scans: the second
        scan of a host reads the first scan's record and skips the URLs it
        has never tested.  The lookup is repeated here until a release of
        the package carries the fix.
        """
        missing_links = []
        if links == "":
            return []
        if isinstance(links, str):
            links = links.splitlines()

        links = [link for link in links if is_on_target(subdomain, link)]
        if not links:
            return []

        self.waitformongo()
        scanid = getattr(self, "scanid", "") or ""
        if not scanid:
            document = self.db["domains"].find_one({"Domain": subdomain})
            if document is None:
                self.log.error("No document found for the specified domain.")
                return []
            scanid = document["Scanid"]

        document = self.db["scans"].find_one({"_id": ObjectId(scanid)})
        if document is None:
            self.log.error(f"No scan document found for the scan id {scanid}.")
            return []
        existing = document.get("ScanLinks", {}).get(self.identity, [])
        missing_links = [link for link in links if link not in existing]
        if missing_links:
            self.db["scans"].update_one(
                {"_id": ObjectId(scanid)},
                {"$push": {f"ScanLinks.{self.identity}": {"$each": missing_links}}},
            )
        return missing_links

    def scan(self,url,headers):
        if self.source == "subrecon":
            
            result=self.nucleiscansingle(url,headers)
        else:
            data=self.url_list(self.source, url)
            result=self.nucleiscanfile(data,headers)

        return result
        
        
    def process(self, task: Task) -> None:
        source = task.payload["source"]
        self.source=source
        self.scanid=task.payload_persistent["scan_id"]
        report_id=task.payload_persistent["report_id"]
        self.report_id=report_id

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

            headers=self.auth_headers(task)
            result=self.scan(url,headers)
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


def is_on_target(subdomain, link):
    """Is the link part of the target?

    A crawler collects the third-party links of a page as well.  A
    scanner that is handed the raw list probes those hosts instead of the
    target.  The comparison ignores the scheme and the path, and it takes
    the port into account, because the target is named as host:port.
    """
    if not link:
        return False
    target_host, _, target_port = (subdomain or "").partition(":")
    target_host = target_host.lower()

    candidate = str(link).strip()
    if "://" in candidate:
        candidate = candidate.split("://", 1)[1]
    candidate = candidate.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in candidate:
        candidate = candidate.rsplit("@", 1)[1]
    host, _, port = candidate.partition(":")

    if host.lower() != target_host:
        return False
    if target_port and port != target_port:
        return False
    return True
