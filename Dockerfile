FROM blacktourmaline/kali
ENV PYTHONUNBUFFERED 1
#	apt-get upgrade -y; \
RUN set -ex; \
    	apt-get update; \
	apt-get remove -y wmis; \
	apt-get -y install --no-install-recommends --allow-unauthenticated \
	python3 wmi-client python3-pip \
	python3-setuptools \
	screen \
	; \
	rm -rf /var/lib/apt/lists/* ;

RUN mkdir /opt/winmap
WORKDIR /opt/winmap

COPY requirements.txt /opt/winmap/requirements.txt

RUN set -ex; \
	pip3 install -r requirements.txt

COPY wmi_to_es.py /opt/winmap/wmi_to_es.py


