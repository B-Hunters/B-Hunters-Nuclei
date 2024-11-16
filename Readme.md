# B-Hunters-Nuclei

**This module is used for vulnerability scanning in [B-Hunters Framework](https://github.com/B-Hunters/B-Hunters) using [Nuclei](https://github.com/projectdiscovery/nuclei).**


## Requirements

To be able to use all the tools remember to update the environment variables with your API keys in `docker-compose.yml` file as some tools will not work well until you add the API keys.

## Usage 

**Note: You can use this tool inside [B-hunters-playground](https://github.com/B-Hunters/B-Hunters-playground)**   
To use this tool inside your B-Hunters Instance you can easily use **docker-compose.yml** file after editing `b-hunters.ini` with your configuration.

**scan_type** environment variable is used if you want to scan paths and domains or only subdomains.   
**Full** Means scan all. anything else mean scan only subdomains. 
# 1. **Build local**
Rename docker-compose.example.yml to docker-compose.yml and update environment variables.

```bash
docker compose up -d
```

# 2. **Docker Image**
You can also run using docker image
```bash
docker run -d -e scan_type=Full  -v $(pwd)/b-hunters.ini:/etc/b-hunters/b-hunters.ini bormaa/b-hunters-nuclei:v1.0
```

## How it works

B-Hunters-Nuclei receives the domain from B-Hunters-Subrecon module and paths from different tools and run scanning on it.   

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/bormaa)
