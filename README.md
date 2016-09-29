# Holmes-Gateway [![Build Status](https://travis-ci.org/HolmesProcessing/Holmes-Gateway.svg?branch=master)](https://travis-ci.org/HolmesProcessing/Holmes-Gateway)

## Overview
Holmes-Gateway orchestrates the submission of objects and tasks to HolmesProcessing. Foremost, this greatly simplifies the tasking and enables the ability to automatically route tasks to [Holmes-Totem](https://github.com/HolmesProcessing/Holmes-Totem) and [Holmes-Totem-Dynamic](https://github.com/HolmesProcessing/Holmes-Totem-Dynamic) at a Service level. In addition, Holmes-Gateway provides validation and authentication. Finally, Holmes-Gateway provides the technical foundation for collaboration between organizations. 

Holmes-Gateway consists of two components:
The Master-Gateway and the Slave-Gateway (also known as Organizational Gateway).
Holmes-Gateway is meant to prevent a user from directly connecting to [Holmes-Storage](https://github.com/HolmesProcessing/Holmes-Storage) or RabbitMQ.
Instead tasking-requests and object upload pass through Holmes-Gateway, which performs validity checking, enforces ACL, and forwards the requests.

A user always connects to the Master-Gateway of their own organization.

If the user wants to upload samples, he sends the request to `/samples/` along with his credentials, and the request will be forwarded to storage.

If the user wants to task the system, he sends the request to `/task/` along with his credentials. The Master-Gateway will parse the submitted tasks and find partnering organizations (or the user's own organization) which have access to the sources that are specified by the tasks.
It will then forward the tasking-requests to the corresponding Slave-Gateways and these will check the task and forward it to to their Rabbit queues.
Slave-Gateways can be configured to only accept requests for certain services for certain organizations and to push different services into different queues.

This way Slave-Gateway can push long-lasting tasks (usually those that perform dynamic analysis) into different queues than quick tasks and thus distribute those tasks among different instances of [Holmes-Totem](https://github.com/HolmesProcessing/Holmes-Totem) and [Holmes-Totem-Dynamic](https://github.com/HolmesProcessing/Holmes-Totem-Dynamic).

### Highlights
* Collaborative tasking: Holmes-Gateway allows organizations to enable other organizations to execute analysis-tasks on their samples without actually give them access to these samples.
* ACL enforcement: Users who want to submit tasks or new objects need to authenticate before they can do so. Also an organization can decide which services an other organization is allowed to execute on their samples.
* Central point for tasking and sample upload: Without Holmes-Gateway, a user who wants to task the system needs access to RabbitMQ, while a user who wants to upload samples needs access to Holmes-Storage.


## USAGE
### Setup
First build Master-Gateway. Make sure to fetch all missing dependencies with `go get`:

```sh
go build
```

#### Starting Master-Gateway
For the SSL-Connection between the user and the Master-Gateway, the Master-Gateway needs to have a valid SSL-Certificate.
If you don't have one, you can create one by executing
```sh
./mkcert.sh
```

Copy the file config-master.json.example to config-master.json and edit it to suit your needs.
The following configuration options are available:
* **HTTP**: The binding for the http-listener
* **SourcesKeysPath**: The path to where the public keys of the sources are found. The keys must be in PEM-format and must have the file-extension \*.pub
* **TicketSignKeyPath**: Path to the private key which is used for signing tickets
* **Organizations**: The list of all known slave-gateways. In the future, this may move to be dynamically configurable from Holmes-Storage. For each Organization a Name, the URI, and the list of sources must be given.
* **OwnOrganization**: The name of the own organization. An organization with this name must also be present in the list of organizations. This organization is used for automatic tasking.
* **AllowedUsers**: A dict mapping the usernames of allowed users to their bcrypt-password-hash. In the future, the credentials will be stored in Holmes-Storage instead.
**NOTE:** The library used for checking the passwords does not support all the possible algorithms for bcrypt. To make sure that your passwords are accepted, it is recommended to use blowfish (hash starts with "$2a$"). Keep an eye on the output of your master-gateway, if your password is not accepted.
* **StorageURI**: The URI to where storage resides for uploading samples
* **AutoTasks**: A dict mapping the mimetype to a dict of tasks, that should be executed automatically whenever a sample is uploaded. The mimetype returned by storage is checked against every value in the dict. If the value from the dict is contained in the returned value, all the corresponding tasks are executed. e.g.: `{"PE32":{"PEINFO":[],"PEID":[]}, "":{"YARA":[]}}` means that for every uploaded file the service "YARA" is executed (since every string contains ""). Additionally, files with a memetype, which contains "PE32", the services "PEINFO" and "PEID" are executed.
* **CertificateKeyPath**: The path to the key of the HTTPS-certificate
* **CertificatePath**: The path to the HTTPS-certificate
* **MaxUploadSize**: The maximum allowed size in MB for uploading samples. Defaults to 200 MB, if no value is configured

Start up the Master-Gateway by calling

```sh
./Holmes-Gateway --master --config config/gateway-master.conf
```


#### Starting Gateway
Make sure, RabbitMQ is running. If it isn't configured to automatically start, start it by executing as root:

```sh
rabbitmq-server
```

Copy the file config.json.example to config.json and edit it to suit your needs.
The following configuration options are available:
* **HTTP**: The binding for the http-listener
* **SourcesKeysPath**: The path to where the private keys of the sources are found. The keys must be in PEM-format and must have the file-extension \*.priv
* **TicketKeysPath**: The public keys for tickets that should be acceptable
* **SampleStorageURI**: The URI where the samples reside. This URI is prepended to the PrimaryURI- and SecondaryURI-fields for incoming tasks
* **AllowedTasks**: A dict indicating, which organization is allowed to request which task. To allow all tasks of an organization use the wildcard '\*'.
* **RabbitURI**: The URI to rabbit
* **RabbitUser**: The rabbit username
* **RabbitPassword**: The rabbit password
* **RabbitDefault**: The default rabbit queue, exchange, and routing-key used for tasks
* **Rabbit**: A dict mapping service names to different queues, exchanges, and routing-keys

Start up the gateway by calling

```sh
./Holmes-Gateway --config config/gateway.conf
```

#### Distributing Keys
Holmes-Gateway uses RSA keys for encrypting tasking-requests based on their source and for signing tickets. Tickets are used, so Slave-Gateways can verify the Master-Gateways of organizations that request tasks.
For this reason, it is important that a Master-Gateway has access to the public keys of all sources. If a Master-Gateway gets a request for a source it has no public key for, it will not forward that request. Furthermore, the Master-Gateway needs access to its organization-specific private key for signing the tickets.
The Slave-Gateways, on the other hand, need access to the private keys of the sources the organization wants to accept, in order to decrypt the tasking requests. Furthermore, the Slave-Gateway needs access to the public key of all the Master-Gateways that are allowed to task the system in order to validate their tickets.
Both, Slave-Gateway, and Master-Gateway will dynamically load new and modified keys from the configured directories during runtime. It is important that the keys are named correctly.
Private keys need to have the extension \*.priv and public keys need to have the extension \*.pub.
The name of the key must match the name of the source or the organization it is used for (this also holds for the key which is used for signing tickets).
The keys can be created using the script `config/keys/generate_key.go`:
```sh
cd config/keys/
go build
./keys sources/src1
```
This will create a public key `sources/src1.pub` and a private key `sources/src1.priv`

**NOTE:** All the keys must be unencrypted, so you should adjust the access-privileges accordingly. Also, the keys created by this script are of size 2048. However, the system does not impose any restriction on the sice, so you can change that, if you feel that a keysize of 2048 is to small. However, your keys must be RSA and in PEM format.

### Example: Routing Different Services To Different Queues:
By modifying gateway's config-file, it is possible to push different services into different RabbitMQ-queues / exchanges.
This way, it is possible to route some services to Holmes-Totem-Dynamic.
The keys **RabbitDefault** and **Rabbit** are used for this purpose. **Rabbit** consists of a dict mapping service-names to RabbitMQ-Queues, Exchanges, and RoutingKeys. If the service is not found in this dict, the values from RabbitDefault are taken.
e.g.
```json
"RabbitDefault": {"Queue": "totem_input", "Exchange": "totem", "RoutingKey": "work.static.totem"},
"Rabbit":        {"CUCKOO":     {"Queue": "totem_dynamic_input", "Exchange": "totem_dynamic", "RoutingKey": "work.static.totem"},
                  "DRAKVUF":    {"Queue": "totem_dynamic_input", "Exchange": "totem_dynamic", "RoutingKey": "work.static.totem"},
                  "VIRUSTOTAL": {"Queue": "totem_dynamic_input", "Exchange": "totem_dynamic", "RoutingKey": "work.static.totem"}}
```
This configuration will route services CUCKOO and DRAKVUF to the queue "totem_dynamic_input", while every other service is routed to "totem_input".


### Uploading Samples:
In order to upload samples to storage, the user sends an https-encrypted request
to `/samples/` of the master-gateway. The master-gateway will forward every request
for this URI directly to storage.
If storage signals a success, master-gateway will immediately issue a tasking-request
for the new samples, if the configuration-option **AutoTasks** is not empty.

You can use [Holmes-Toolbox](https://github.com/HolmesProcessing/Holmes-Toolbox)
for this purpose. Just replace the storage-URI with the URI of master-gateway.
Also make sure, your SSL-Certificate is accepted. You can do so either by adding it to your system's certificate store or by using the command-line option `--insecure`.
The following command uploads all files from the directory $dir to the Master-Gateway residing at 127.0.0.1:8090 using 5 threads.
```sh
./Holmes-Toolbox --gateway https://127.0.0.1:8090 --user test --pw test --dir $dir --src foo --comment something --workers 5 --insecure
```

### Requesting a Task:
In order to request a task, a user sends an https-request (GET/POST) to the master-gateway
containing the following form-fields:
* **username**: The user's login-name
* **password**: The user's password
* **task**: The task which should be executed in json-form, as described below.

A task consists of the following attributes:
* **primaryURI**: The user enters only the sha256-sum here, as the Gateway will
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
curl --data 'username=test&password=test&task=[{"primaryURI":"3a12f43eeb0c45d241a8f447d4661d9746d6ea35990953334f5ec675f60e36c5","secondaryURI":"","filename":"myfile","tasks":{"PEINFO":[],"YARA":[]},"tags":["test1"],"attempts":0,"source":"src1","download":true}]' --insecure https://localhost:8090/task/
```

Alternatively, it is possible to use Holmes-Toolbox for this task, as well. First a file must be prepared containing a line with the sha256-sum, the filename, and the source (separated by single spaces) for each sample.
```sh
./Holmes-Toolbox --gateway https://127.0.0.1:8090 --tasking --file sampleFile --user test --pw test --tasks '{"PEINFO":[], "YARA":[]}' --tags '["mytag"]' --comment 'mycomment' --insecure
```

If no error occured, nothing or an empty list will be returned. Otherwise a list containing the
faulty tasks, as well as a description of the errors will be returned.

You can also use the Web-Interface by opening the file `submit_task.html` in your browser. However, you will need to create an exception for the certificate by visiting the website of the master-gateway manually, before you can use the web interface.
