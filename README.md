# Holmes-Gateway
Main program for receiving tasking and objects. It validates input, checks authentication, and pushes the requests to the pipeline.

# USAGE
## Setup
First build Master-Gateway. Make sure to fetch all missing dependencies with **go get**:

```sh
go build
```

### Starting Master-Gateway
If you don't have an SSL-Certificate, create one by executing
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
* **AllowedUsers**: A dict mapping the usernames of allowed users to their bcrypt-password-hash. In the future, the credentials will be stored in Holmes-Storage instead
* **StorageURI**: The URI to where storage resides for uploading samples
* **AutoTasks**: A dict for tasks, that should be executed automatically whenever a sample is uploaded.
* **CertificateKeyPath**: The path to the key of the HTTPS-certificate
* **CertificatePath**: The path to the HTTPS-certificate

Start up the master-gateway by calling

```sh
./Holmes-Gateway --master --config config/gateway-master.conf
```


### Starting Gateway
Make sure, rabbitmq is running. If it isn't configured to automatically start, start it byexecuting as root:

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

### Example: Routing Different Services To Different Queues:
By modifying gateway's config-file, it is possible to push different services into different RabbitMq-queues / exchanges.
This way, it is possible to route some services to Holmes-Totem-Dynamic.
The keys **RabbitDefault** and **Rabbit** are used for this purpose. **Rabbit** consists of a dict mapping service-names to RabbitMq-Queues, Exchanges, and RoutingKeys. If the service is not found in this dict, the values from RabbitDefault are taken.
e.g.
```json
"RabbitDefault": {"Queue": "totem_input", "Exchange": "totem", "RoutingKey": "work.static.totem"},
"Rabbit":        {"CUCKOO":     {"Queue": "totem_dynamic_input", "Exchange": "totem_dynamic", "RoutingKey": "work.static.totem"},
                  "DRAKVUF":    {"Queue": "totem_dynamic_input", "Exchange": "totem_dynamic", "RoutingKey": "work.static.totem"},
                  "VIRUSTOTAL": {"Queue": "totem_dynamic_input", "Exchange": "totem_dynamic", "RoutingKey": "work.static.totem"}}
```
This configuration will route services CUCKOO and DRAKVUF to the queue "totem_dynamic_input", while every other service is routed to "totem_input".


## Uploading Samples:
In order to upload samples to storage, the user sends an https-encrypted request
to */samples/* of the master-gateway. The master-gateway will forward every request
for this URI directly to storage.
If storage signals a success, master-gateway will immediately issue a tasking-request
for the new samples, if the configuration-option **AutoTasks** is not empty.

You can use [Holmes-Toolbox](https://github.com/HolmesProcessing/Holmes-Toolbox)
for this purpose. Just replace the storage-URI with the URI of master-gateway.
Also make sure, your SSL-Certificate is accepted. You can do so either by adding it to your system's certificate store or by using the command-line option *--insecure*.
The following command uploads all files from the directory $dir to the Master-Gateway residing at 127.0.0.1:8090 using 5 threads.
```sh
./Holmes-Toolbox --gateway https://127.0.0.1:8090 --user test --pw test --dir $dir --src foo --comment something --workers 5 --insecure
```

## Requesting a Task:
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
The *--insecure* parameter is used, to disable certificate checking.

```sh
curl --data 'username=test&password=test&task=[{"primaryURI":"3a12f43eeb0c45d241a8f447d4661d9746d6ea35990953334f5ec675f60e36c5","secondaryURI":"","filename":"myfile","tasks":{"PEINFO":[],"YARA":[]},"tags":["test1"],"attempts":0,"source":"src1","download":true}]' --insecure https://localhost:8090/task/
```

Alternatively, it is possible to use Holmes-Toolbox for this task, as well. First a file must be prepared containing a line with the sha256-sum, the filename, and the source (separated by single spaces) for each sample.
```sh
./Holmes-Toolbox --gateway https://127.0.0.1:8090 --tasking --file sampleFile --user test --pw test --tasks '{"PEINFO":[], "YARA":[]}' --tags '["mytag"]' --comment 'mycomment' --insecure
```

If no error occured, nothing or an empty list will be returned. Otherwise a list containing the
faulty tasks, as well as a description of the errors will be returned.

You can also use the Web-Interface by opening the file *submit_task.html* in your browser. However, you will need to create an exception for the certificate by visiting the website of the master-gateway manually, before you can use the web interface.
