# This stage is used to get pre-compiled arangodb client binaries.
FROM arangodb:3.12.4 AS deps

# This stage installs dependencies to build and load BRON into arangodb. 
FROM python:3.12-slim AS runtime

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y git
    
WORKDIR /usr/local/bron
COPY requirements.txt .
RUN pip3 install -r requirements.txt

COPY --from=deps /usr/bin/arangoimport /usr/bin/.
COPY --from=deps /etc/arangodb3/arangoimport.conf /etc/arangodb3/arangoimport.conf
COPY --from=deps /usr/bin/arangoexport /usr/bin/.
COPY --from=deps /etc/arangodb3/arangoexport.conf /etc/arangodb3/arangoexport.conf
COPY . .

ENV DATA_DIR=$dir

ENV PYTHONPATH="$PYTHONPATH:/usr/local/bron"
CMD ./bootstrap.sh