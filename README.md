# Holmes-Gateway [![Build Status](https://travis-ci.org/HolmesProcessing/Holmes-Gateway.svg?branch=master)](https://travis-ci.org/HolmesProcessing/Holmes-Gateway)

## Overview
Holmes-Gateway orchestrates the submission of objects and tasks to HolmesProcessing. Foremost, this greatly simplifies the tasking and enables the ability to automatically route tasks to [Holmes-Totem](https://github.com/HolmesProcessing/Holmes-Totem) and [Holmes-Totem-Dynamic](https://github.com/HolmesProcessing/Holmes-Totem-Dynamic) at a Service level. In addition, Holmes-Gateway provides validation and authentication. Finally, Holmes-Gateway provides the technical foundation for collaboration between organizations. 

Holmes-Gateway is meant to prevent a user from directly connecting to [Holmes-Storage](https://github.com/HolmesProcessing/Holmes-Storage) or RabbitMQ.
Instead tasking-requests and object upload pass through Holmes-Gateway, which performs validity checking, enforces ACL, and forwards the requests.

If the user wants to upload samples, he sends the request to `/samples/` along with his credentials, and the request will be forwarded to storage.

If the user wants to task the system, he sends the request to `/task/` along with his credentials. Holmes-Gateway will parse the submitted tasks and find partnering organizations (or the user's own organization) which have access to the sources that are specified by the tasks.
It will then forward the tasking-requests to the corresponding Gateways and these will check the task and forward it to to their AMQP queues.
Gateway can be configured to push different services into different queues.

This way Gateway can push long-lasting tasks (usually those that perform dynamic analysis) into different queues than quick tasks and thus distribute those tasks among different instances of [Holmes-Totem](https://github.com/HolmesProcessing/Holmes-Totem) and [Holmes-Totem-Dynamic](https://github.com/HolmesProcessing/Holmes-Totem-Dynamic).

### Highlights
* Collaborative tasking: Holmes-Gateway allows organizations to enable other organizations to execute analysis-tasks on their samples without actually giving them access to these samples.
* ACL enforcement: Users who want to submit tasks or new objects need to authenticate before they can do so.
* Central point for tasking and sample upload: Without Holmes-Gateway, a user who wants to task the system needs access to RabbitMQ, while a user who wants to upload samples needs access to Holmes-Storage.


## USAGE
### Setup
#### Building
First build Gateway. Make sure to fetch all missing dependencies with `go get`:

```sh
go get ./...
go build
```
#### Configuration
Gateway uses an SSL-Connection and therefore needs to have a valid SSL-Certificate.
If you don't have one, you can create one by executing
```sh
cd config
./mkcert.sh
```
Doing this will create the files `cert-key.pem` and `cert.pem`. You will need to refer to these files later from the configuration.

Copy the file `config/gateway.conf.example` to `config/gateway.conf` and edit it to suit your needs.
The following configuration options are available:
* **HTTP**: The binding for the http-listener
* **StorageSampleURI**: The URI to where storage resides for uploading samples. This URI is also prepended to the URIs for tasking-requests.
* **Organizations**: The list of all known partnering organizations. For each Organization a Name, the URI of the organization's gateway, and the list of sources must be given. For the own organization, no URI must be given.
* **OwnOrganization**: The name of the own organization. An organization with this name must also be present in the list of organizations. This organization is used for automatic tasking.
* **AllowedUsers**: A dict mapping the usernames of allowed users to their bcrypt-password-hash. In the future, the credentials will be stored in Holmes-Storage instead.
**NOTE:** The library used for checking the passwords does not support all the possible algorithms for bcrypt. To make sure that your passwords are accepted, it is recommended to use blowfish (hash starts with "$2a$").
* **AutoTasks**: A dict mapping the mimetype to a dict of tasks, that should be executed automatically whenever a sample is uploaded. The mimetype returned by storage is checked against every value in the dict. If the value from the dict is contained in the returned value, all the corresponding tasks are executed. e.g.: `{"PE32":{"PEID":[]}, "":{"YARA":[]}}` means that for every uploaded file the service "YARA" is executed (since every string contains ""). Additionally, files with a memetype, which contains "PE32", the service "PEID" is executed.
* **DisableStorageVerify**: If set to true, the certificate of Holmes-Storage is not checked for validity
* **AllowForeignTasks**: If set to true, tasks from other gateways will be accepted, otherwise only tasks sent from authenticated users will be accepted. Note that at the moment, it is not possible to configure a more fine grained ACL-concept
* **CertificateKeyPath**: The path to the key of the HTTPS-certificate
* **CertificatePath**: The path to the HTTPS-certificate
* **MaxUploadSize**: The maximum allowed size in MB for uploading samples. Defaults to 200 MB, if no value is configured
* **AMQP**: The AMQP-connection-information
* **AMQPDefault**: The Queue, Exchange, and RoutingKey that are used, if no more specific match is found in *AMQPSplitting*.
* **AMQPSplitting**: A dict mapping service names to different Queues, Exchanges, and RoutingKeys.


#### Starting
Make sure, your AMQP-server (e.g. RabbitMQ) is running.
You can start RabbitMQ by executing:
```sh
sudo rabbitmq-server
```
Once the AMQP-server is running, you can start up gateway:
```sh
./Holmes-Gateway --config config/gateway.conf
```

### Example: Routing Different Services To Different Queues:
By modifying gateway's config-file, it is possible to push different services into different AMQP-queues / exchanges.
This way, it is possible to route some services to Holmes-Totem-Dynamic.
The keys **AMQPDefault** and **AMQPSplitting** are used for this purpose. **AMQPSplitting** consists of a dict mapping service-names to Queues, Exchanges, and RoutingKeys. If the service is not found in this dict, the values from AMQPDefault are taken.
e.g.
```json
"AMQPDefault":   {"Queue": "totem_input", "Exchange": "totem", "RoutingKey": "work.static.totem"},
"AMQPSplitting": {"CUCKOO":     {"Queue": "totem_dynamic_input", "Exchange": "totem_dynamic", "RoutingKey": "work.static.totem"},
                  "DRAKVUF":    {"Queue": "totem_dynamic_input", "Exchange": "totem_dynamic", "RoutingKey": "work.static.totem"},
                  "VIRUSTOTAL": {"Queue": "totem_dynamic_input", "Exchange": "totem_dynamic", "RoutingKey": "work.static.totem"}}
```
This configuration will route services CUCKOO and DRAKVUF to the queue "totem_dynamic_input", while every other service is routed to "totem_input".


### Uploading Samples:
In order to upload samples to storage, the user sends an HTTPS-encrypted POST request
to `/samples/` of the Holmes-Gateway.
Gateway will forward every request for this URI directly to storage.
If storage signals a success, Gateway will immediately issue a tasking-request
for the new samples, if the configuration-option **AutoTasks** is not empty.

You can use [Holmes-Toolbox](https://github.com/HolmesProcessing/Holmes-Toolbox)
for this purpose. Just replace the storage-URI with the URI of Gateway.
Also make sure, your SSL-Certificate is accepted. You can do so either by adding it to your system's certificate store or by using the command-line option `--insecure`.
The following command uploads all files from the directory $dir to the Gateway instance residing at 127.0.0.1:8090 using 5 threads.
```sh
./Holmes-Toolbox --gateway https://127.0.0.1:8090 --user test --pw test --dir $dir --src foo --comment something --workers 5 --insecure
```

### Requesting a Task:
In order to request a task, a user sends an HTTPS-request (GET/POST) to Gateway
containing the following form-fields:
* **username**: The user's login-name
* **password**: The user's password
* **task**: The task which should be executed in json-form, as described below.

A task consists of the following attributes:
* **primaryURI**: The user enters only the sha256-sum here, as Gateway will
prepend this with the URI to its version of Holmes-Storage
* **secondaryURI** (optional): A secondary URI to the sample, if the primaryURI isn't found
* **filename**: The name of the sample
* **tasks**: All the tasks that should be executed, as a dict
* **tags**: A list of tags associated with this task
* **attempts**: The number of attempts. Should be zero
* **source**: The source this sample belongs to. The executing organization is chosen mainly based on this value
* **download**: A boolean specifying, whether totem has to download the file given as PrimaryURI

For this purpose any webbrowser or commandline utility can be used.
The following demonstrates an exemplary evocation using CURL.
The `--insecure` parameter is used, to disable certificate checking.

```sh
curl --data 'username=test&password=test&task=[{"primaryURI":"3a12f43eeb0c45d241a8f447d4661d9746d6ea35990953334f5ec675f60e36c5","secondaryURI":"","filename":"myfile","tasks":{"PEID":[],"YARA":[]},"tags":["test1"],"attempts":0,"source":"src1","download":true}]' --insecure https://localhost:8090/task/
```

Alternatively, it is possible to use Holmes-Toolbox for this task, as well. First a file must be prepared containing a line with the sha256-sum, the filename, and the source (separated by single spaces) for each sample.
```sh
./Holmes-Toolbox --gateway https://127.0.0.1:8090 --tasking --file sampleFile --user test --pw test --tasks '{"PEID":[], "YARA":[]}' --tags '["mytag"]' --comment 'mycomment' --insecure
```

If no error occured, nothing or an empty list will be returned. Otherwise a list containing the
faulty tasks, as well as a description of the errors will be returned.

You can also use the Web-Interface by opening the file `submit_task.html` in your browser. However, you will need to create an exception for the certificate by visiting the website of the Gateway manually, before you can use the web interface.
