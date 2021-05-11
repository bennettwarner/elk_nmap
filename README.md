# Elastic stack (ELK) on Docker for the Ingest of NMAP scan results

based entirely on the awesome work from:

    https://github.com/deviantony/
    https://github.com/ChrisRimondi
    https://github.com/marco-lancini
    https://github.com/happyc0ding/

Changes from @marco-lancini's repo include bumping up to a current version of the ELK stack and a refactor of the python ingestor to include the hostscript attribute from scans.


## Instructions

* Start up stack with:

    ```
    docker-compose up --build -d
    ```
* Place files in import and run:

    ```
    docker-compose run -e PROJECT=proj_name ingestor
    ```