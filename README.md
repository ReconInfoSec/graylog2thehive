# graylog2thehive

Create alerts in [The Hive](https://github.com/TheHive-Project/TheHive) from your [Graylog](https://github.com/Graylog2/graylog2-server/) alerts, to be turned into Hive cases.

Simple Python flask app that runs as a web server, and accepts POST requests from your Graylog `HTTP Alarm Callback` notifications.

```
git clone https://github.com/ReconInfoSec/graylog2thehive.git /opt/graylog2thehive
```

Get up and running:
* Configure SSL certificate paths in `app.py`, or remove all context lines if not using SSL
* Copy `init.d/graylog2thehive.service` to `/etc/systemd/system/graylog2thehive.service`
* Set your Hive API key in `/etc/systemd/system/graylog2thehive.service` for the `HIVE_SECRET_KEY`
* Set your Hive and Graylog URLs in `config.py`

```
pip install -r requirements.txt
systemctl enable graylog2thehive
systemctl start graylog2thehive
```

* Runs at https://0.0.0.0:5000, accepts POST requests at `/create_alert`
* Point your Graylog `HTTP Alarm Callback` to `https://[YOURSERVER].com:5000/create_alert`
