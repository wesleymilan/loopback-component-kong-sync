# Loopback Component Kong Sync

Tested with Loopback JS 3 (https://loopback.io/) and Kong 1.1.2 (https://konghq.com/)

This is a Loopback JS component to synchronize routes to Kong API Gateway.

This component map all Models and Methods from Loopback standardizing it and creating the 
related routes in Kong. 

#### How it works:
- Read and map all public models
- Read and map all public methods from public models
- Read Service and resources from Kong
- Compare LB resources with Kong Resources based on MD5 checksum stored as tags on Kong
- Create resources if they don't exist and update in case of changes have being made on LB
- Create targets using local IP or the IP list con config file

#### Setup
Installing using npm:
`npm install git+https://github.com/wesleymilan/node-kong-admin.git --save`

After installing it on your project folder you have to input your preferences on 
`component-config.json`

#### component-config.json sessions

The plugin declaration must be inside `loopback-component-kong-sync` index.
You can find a full example of this file in `component-config.example.json`.

##### appVersion: 
You can use this param as a deploy key. Specifying an index of `process.env`
the value of this environment variable will be used on all checksum to ensure that all 
resource will be replaced on kong when you release a new API version.

i.e.: `APP_VERSION`
In this case the value of `process.env.APP_VERSION` now is a part of checksum to determine 
if the LB resources have being modified and must be replaced on Kong.

##### adminUrl: 
Kong admin URL. As you should keep your admin URL private we recommend you set 
here an internal IP of your network.

i.e.: `http://admin.kong.local:8001`

##### apiHost: 
This is your API host address that should be exposed publicity.

i.e.: `api.mywebsite.com`

##### service: 
This param parses the same object as Kong Service Object (https://docs.konghq.com/1.2.x/admin-api/#service-object)

i.e.:
```
"service": {
    "name": "SyncService",
    "retries": 5,
    "protocol": "http",
    "host": "SyncUpstream",
    "port": 80,
    "path": "/",
    "connect_timeout": 60000,
    "write_timeout": 60000,
    "read_timeout": 60000,
    "tags": [
        "SyncService"
    ]
}
```

##### upstream:
This param parses the same object as Kong Upstream Object (https://docs.konghq.com/1.2.x/admin-api/#upstream-object)

i.e.:
```
"upstream": {
    "name": "SyncUpstream",
    "hash_on": "none",
    "hash_fallback": "none",
    "slots": 10000,
    "healthchecks": {
        "active": {
            "https_verify_certificate": false,
            "unhealthy": {
                "http_statuses": [429, 404, 500, 501, 502, 503, 504, 505],
                "timeouts": 2,
                "http_failures": 2,
                "interval": 100
            },
            "http_path": "/",
            "timeout": 1,
            "healthy": {
                "http_statuses": [200, 301, 302, 307],
                "interval": 5,
                "successes": 2
            },
            "concurrency": 10,
            "type": "http"
        }
    },
    "tags": [
        "SyncUpstream",
        "SyncService"
    ]
}
```

##### targets:
This param parses the same object as Kong Target Object (https://docs.konghq.com/1.2.x/admin-api/#target-object)

i.e.:
```
"targets": [
    {
        "target": "127.0.0.1:3001",
        "weight": 100,
        "tags": [
            "SyncTarget",
            "SyncUpstream",
            "SyncService"
        ]
    },
    {
        "target": null,
        "weight": 100,
        "tags": [
            "SyncTarget",
            "SyncUpstream",
            "SyncService"
        ]
    }
]
```

##### plugins:
This param parses the same object as Kong Plugin Object (https://docs.konghq.com/1.2.x/admin-api/#plugin-object)

The plugin object must be inside `service` or `route`. You don't have to set service or route 
fields on plugin object, it will be replaced automatically by the service. In case of you
setting plugin into route, this plugin will be settled for all routes of your API, except
those one you override on model, see bellow.

This component was developed to work with `key-auth` plugin, so we recommend you set this plugin
on route option.  

You can find all bundle Kong plugin here https://docs.konghq.com/hub/. 

i.e.:
```
"plugins": {
    "service": {
        "cors": {
            "name": "cors",
            "service": null,
            "route": null,
            "enabled": true,
            "run_on": "first",
            "protocols": ["http", "https"],
            "tags": [
                "SyncService",
                "cors"
            ],
            "config": {
                "origins": [
                    "https://www.mywebsite.com",
                    "https://mywebsite.com"
                ],
                "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"],
                "headers": [
                    "Origin",
                    "Referer",
                    "Authorization",
                    "Accepts",
                    "Content-Length",
                    "Content-Type",
                    "User-Agent",
                    "Host",
                    "Connection",
                    "Accept-Language",
                    "Accept-Encoding",
                    "Accept-Charset"
                ],
                "exposed_headers": [
                    "User-Agent",
                    "Access-Control-Allow-Origin"
                ],
                "credentials": true,
                "max_age": 3600,
                "preflight_continue": true
            }
        }
    },
    "route": {
        "key-auth": {
            "name": "key-auth",
            "service": null,
            "route": null,
            "enabled": true,
            "run_on": "first",
            "protocols": ["http", "https"],
            "tags": [
                "SyncRoute",
                "key-auth"
            ],
            "config": {
                "key_names": ["authorization","Authorization"],
                "key_in_body": false,
                "hide_credentials": false,
                "anonymous": null,
                "run_on_preflight": false
            }
        }
    }
}
```

##### authentication:
Setting the login methods the component will intercept well succeeded logins and 
create the consumer and the credential automatically on Kong. The same will happens when
a logout method is requested, LB component will keep the consumer but will remove 
the credential.

`simultaneousSessions` is used to avoid Kong database to be overloaded with unused
credentials, so all credentials exceeding the max number of simultaneous sessions
will be removed from Kong even if they are still valid.

i.e.:
```
"authentication": {
    "simultaneousSessions": 5,
    "loginMethods": [
        "/users/login",
        "/users/create",
        "/users/confirm",
        "/users/verify"
    ],
    "logoutMethods": [
        "/users/logout"
    ]
}
```

## Models setup
On `model-config.json` you can override some default options using the param `kong`.

##### Force a method to not be included on Kong even if it's a public method
```
"MyModel": {
    "dataSource": "mysql",
    "public": true,
    "options": {
        "remoting": {
            "sharedMethods": {
                "*": false,
                "search": true
            }
        }
    },
    "kong": {
        "methods": {
            "search": {
                "disabled": true
            }
        }
    }
},
```

##### Force an entire model to not be included on Kong even if it's a public model
```
"MyModel": {
    "dataSource": "mysql",
    "public": true,
    "options": {
        "remoting": {
            "sharedMethods": {
                "*": false,
                "search": true
            }
        }
    },
    "kong": {
        "disabled": true
    }
},
```

##### Disabling plugins on routes
```
"MyUserModel": {
    "dataSource": "mysql",
    "public": true,
    "options": {
        "remoting": {
            "sharedMethods": {
                "*": false,
                "login": true,
                "logout": true
            }
        }
    },
    "kong": {
        "methods": {
            "login": {
                "plugins": {
                    "key-auth": {
                        "disabled": true
                    }
                }
            },
            "logout": {
                "plugins": {
                    "key-auth": {
                        "disabled": true
                    }
                }
            }
        }
    }
},
```


























