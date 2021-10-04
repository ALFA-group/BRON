# This stage is used to get pre-compiled arangodb client binaries.
FROM arangodb:3.8.1 AS deps

# This stage installs dependencies to build and load BRON into arangodb. 
FROM python:3.8-slim AS runtime

WORKDIR /usr/local/bron
COPY requirements.txt .
RUN pip3 install -r requirements.txt

COPY --from=deps /usr/bin/arangoimport /usr/bin/.
COPY --from=deps /etc/arangodb3/arangoimport.conf /etc/arangodb3/arangoimport.conf
COPY . .

ENV DATA_DIR=$dir

ENV PYTHONPATH="$PYTHONPATH:/usr/local/bron"
CMD cd graph_db && ./bootstrap.sh
