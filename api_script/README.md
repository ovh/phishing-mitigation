## tilera-phishing API server

Build :
  * python setup.py sdist

Install :
  * extract api_server-1.0.tar.gz
  * go to extracted dir
  * python setup.py install
  * copy your own certificate files to /etc/tilera-phishing/cert/ as specified during install

Run :
  * by default, server is installed in /usr/local/bin/tilera-phishing-api/
  * so you can run :
  * /usr/local/bin/tilera-phishing-api/api_server [-p port_number]


API :

**jsonTargets** :
a json describing a set of targets :
```javascript
{
  "targets":[
    {
      "ip" : "192.168.0.2",
      "url" : "http://www.example.com/index.html"
    },
    {
      "ip" : "192.168.0.1",
      "url" : "http://www.example.com/phish.html"
    }
  ]
}
```

Commands :

| Method   | Endpoint           | payload     | description                 | response            |
| -------- | ------------------ | ----------- | --------------------------- | ------------------- |
| GET      | /v1/targets        |             | list all current targets    | 200 : jsonTargets   |
| POST     | /v1/targets/add    | jsonTargets | add given set of targets    | 200 : sucess        |
| POST     | /v1/targets/remove | jsonTargets | remove given set of targets | 200 : sucess        |
