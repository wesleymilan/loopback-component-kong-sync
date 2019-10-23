const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const ip = require('ip');
const async = require('async');
const debug = require('debug')('loopback:component:kong:sync');
const kongLib = require('node-kong-admin');

const loopback = require('loopback');
const lbConfig = loopback.getConfig();

//console.log('lbConfig: ', lbConfig);

module.exports = function(loopbackApplication, options) {

    let modelsDefinition, kongClient, appVersion, userModel, loginMethods, logoutMethods, instanceOptions;

    function init() {

        if(!options.instances[process.env.INSTANCE]) return;
        instanceOptions = options.instances[process.env.INSTANCE];

        // Check required params
        if(!options.adminUrl) throw new Error('adminUrl is required for Loopback Component Kong Sync');
        if(!options.apiHost) throw new Error('apiHost is required for Loopback Component Kong Sync');
        if(!options.service) throw new Error('service is required for Loopback Component Kong Sync');
        if(!options.upstream) throw new Error('upstream is required for Loopback Component Kong Sync');
        if(!options.targets) throw new Error('targets is required for Loopback Component Kong Sync');

        options.authentication.simultaneousSessions = options.authentication.simultaneousSessions || 5;

        userModel = loopback.getModel('User');

        // Instantiate Kong Client
        kongClient = new kongLib({ url: options.adminUrl });

        // Load model config file starting by environment config
        let modelsDefinitionFile = path.resolve(path.join(__dirname, '..', '..', 'server', 'model-config.' + process.env.NODE_ENV +'.json'));
        if(fs.existsSync(modelsDefinitionFile)) {
            modelsDefinition = require(modelsDefinitionFile);
        } else {
            modelsDefinition = require(path.resolve(path.join(__dirname, '..', '..', 'server', 'model-config.json')));
        }

        debug('Building routes');
        options.routes = kongBuildRoutes();

        debug('Building checksum hashes');
        appVersion = process.env[options.appVersion] ? process.env[options.appVersion] : options.appVersion;
        options.checksum = {};

        buildSessionMethods();

        console.log('Delaying Kong Sync ' + instanceOptions.delay + 's');

        setTimeout(function() {

            syncKong(function(err) {
                if(err) {
                    if(process.env.DEBUG !== 'loopback:component:kong:sync') console.error('An error occurred, for more details use "DEBUG=loopback:component:kong:sync node ."');
                    else console.error(err);
                }
                else console.log('Services synced');
            });

        }, instanceOptions.delay * 1000);

    }

    function syncKong(cb) {

        async.series([

            function(cb) {

                if(instanceOptions.sync.indexOf('upstreams') === -1) {
                    console.log('Skipping Kong Sync UPSTREAMS');
                    return cb();
                }

                console.log('Syncing Kong UPSTREAMS');

                syncUpstream(function(err) {

                    if (err) return cb(err);

                    cb();

                });

            },
            function(cb) {

                if(instanceOptions.sync.indexOf('targets') === -1) {
                    console.log('Skipping Kong Sync TARGETS');
                    return cb();
                }

                console.log('Syncing Kong TARGETS');

                syncTarget(function(err) {

                    if (err) return cb(err);

                    cb();

                });

            },
            function(cb) {

                if(instanceOptions.sync.indexOf('services') === -1) {
                    console.log('Skipping Kong Sync SERVICES');
                    return cb();
                }

                console.log('Syncing Kong SERVICES');

                syncService(function(err) {

                    if (err) return cb(err);

                    cb();

                });

            },
            function(cb) {

                if(instanceOptions.sync.indexOf('routes') === -1) {
                    console.log('Skipping Kong Sync ROUTES');
                    return cb();
                }

                console.log('Syncing Kong ROUTES');

                syncRoutes(function(err) {

                    if(err) return cb(err);

                    cb();

                });

            }

        ], function(err) {

            if(err) return cb(err);

            cb();

        });

    }

    function syncService(cb) {

        debug('Syncing service...');

        kongClient.service.get(options.service.name, function(err, service) {

            if(err) {
                return cb(err);
            }

            options.checksum.service = checksum(JSON.stringify(options.service) + JSON.stringify(options.routes) + appVersion);

            if(!service || service.tags.indexOf(options.checksum.service) === -1) {

                debug('Kong Service Not Synced: ', service);

                options.service.tags.push(options.checksum.service);

                kongClient.service.updateOrCreate(options.service, function(err, service) {

                    if(err) {
                        return cb(err);
                    }

                    if(!service) return cb(new Error('No service created'));

                    options.service = service;

                    debug('Kong Service Created: ', service);

                    syncServicePlugins(cb);

                });

            } else {

                options.service = service;

                debug('Kong Service Found: ', service);

                syncServicePlugins(cb);

            }

        });

    }

    function syncServicePlugins(cb) {

        listServicePlugins(options.service.id, null, {}, function(err, oldPlugins) {

            oldPlugins = oldPlugins || {};

            async.eachSeries(options.plugins.service, function(item, cb) {

                item.service = { "id": options.service.id };

                debug('Plugin: ', item);

                let pluginChecksum = checksum(JSON.stringify(item));

                item.tags.push(pluginChecksum);

                if(!oldPlugins[item.name]) {

                    debug('Create Plugin: ', item);

                    kongClient.plugin.create(item, function (err, created) {

                        if (err) console.error(err);

                        debug('Plugin %j created for service: %j', created, options.service.id);

                        cb();

                    });

                } else if(!oldPlugins[item.name].tags || oldPlugins[item.name].tags.indexOf(pluginChecksum) === -1) {

                    item.id = oldPlugins[item.name].id;

                    debug('Update Plugin: ', item);
                    
                    kongClient.plugin.update(item, function (err, updated) {

                        if (err) console.error(err);

                        delete(oldPlugins[item.name]);

                        debug('Plugin %j updated for service: %j', updated, options.service.id);

                        cb();

                    });

                } else {

                    debug('Plugin is already updated');

                    delete(oldPlugins[item.name]);

                    cb();

                }

            }, function(err) {

                if(oldPlugins.length === 0) return cb();

                deleteOldServicePlugins(oldPlugins, cb);

            });

        });

    }

    function deleteOldServicePlugins(plugins, cb) {

        async.eachSeries(plugins, function(item, cb) {

            debug('Deleting plugin: ', item);

            kongClient.plugin.delete(item.id, function(err, deleted) {

                if(err) console.error(err);

                debug('Plugin Deleted');

                cb();

            });

        }, function(err) {

            cb();

        });

    }

    function listServicePlugins(serviceId, offset, result, cb) {

        debug('Listing plugins');

        if(!result) result = {};

        kongClient.plugin.listByService(serviceId, offset, function(err, plugins) {

            if(err) console.error(err);

            if(!plugins || plugins.data.length === 0) {
                debug('No plugins found');
                return cb();
            }

            async.each(plugins.data, function(item, cb) {

                debug('Plugin: ', item);

                result[item.name] = item;

                cb();

            }, function(err) {

                if(plugins.offset) {
                    debug('Getting next page of routes: ', plugins.offset);
                    return listServicePlugins(serviceId, plugins.offset, result, cb);
                }

                cb(null, result);

            });

        });

    }

    function syncRoutes(cb) {

        debug('Syncing routes...');

        if(!options.oldRoutes) options.oldRoutes = {};

        getRoutes(null, function() {

            debug('Iterate new routes: ');

            //console.log('Routes: ', options.routes);

            async.eachSeries(options.routes, function(item, cb) {

                //console.log('item.name: ', item.name);

                debug('New Route: ', item);

                item.service = { id: options.service.id };

                let plugins = JSON.parse(JSON.stringify(item.plugins));
                //delete item.plugins;

                let routeChecksum = checksum(JSON.stringify(item) + JSON.stringify(plugins) + appVersion);

                item.tags.push(routeChecksum);

                //if(item.name === 'Reserve-listReserves') console.log(options.oldRoutes[item.name].tags, routeChecksum);

                if(!options.oldRoutes[item.name] || options.oldRoutes[item.name].tags.indexOf(routeChecksum) === -1) {

                    debug('New Route not synced: ', item);

                    kongClient.route.updateOrCreate(item, function(err, created) {

                        if(err) {
                            console.error('route.updateOrCreate ERROR: ', err);
                            return cb();
                        }

                        debug('Route created/updated: ', created);

                        syncRoutePlugins(created.id, plugins, cb);

                    });

                } else {

                    debug('New Route already synced: ', item);

                    cb();

                }

                delete(options.oldRoutes[item.name]);

            }, function(err) {

                debug('Sync Routes done');

                removeOldRoutes(cb);

            });

        });

    }

    function getRoutes(offset, cb) {

        debug('Getting routes from service: ', options.service.name, offset);

        kongClient.route.listByService(options.service.name, offset, function(err, routes) {

            if(err) {
                console.error('cleanupRoutes ERROR: ', err);
                return cb();
            }

            if(!routes || routes.data.length === 0) {
                debug('No routes found');
                return cb();
            }

            debug('Iterate old routes');

            async.eachSeries(routes.data, function(item, cb) {

                debug('Old Route: ', item);

                options.oldRoutes[item.name] = item;

                return cb();

            }, function(err) {

                if(routes.next) {
                    debug('Getting next page of routes: ', routes.offset);
                    return getRoutes(routes.offset, cb);
                }

                cb();

            });

        });

    }

    function removeOldRoutes(cb) {

        debug('Cleaning up old routes');

        async.eachSeries(options.oldRoutes, function(item, cb) {

            debug('Removing route: ', item);

            kongClient.route.delete(item.id, function (err, routes) {

                if (err) {
                    console.error(err);
                }

                delete(options.oldRoutes[item.name]);

                debug('Route removed');

                cb();

            });

        }, function(err) {

            cb();

        });

    }

    function syncRoutePlugins(routeId, plugins, cb) {

        listRoutePlugins(routeId, null, {}, function(err, oldPlugins) {

            oldPlugins = oldPlugins || {};

            async.eachSeries(plugins, function(item, cb) {

                item.route = { "id": routeId };

                debug('Plugin: ', item);

                let pluginChecksum = checksum(JSON.stringify(item));

                item.tags.push(pluginChecksum);

                if(!oldPlugins[item.name]) {

                    debug('Create Plugin: ', item);

                    kongClient.plugin.create(item, function (err, created) {

                        if (err) console.error(err);

                        debug('Plugin %j created for route: %j', created, routeId);

                        cb();

                    });

                } else if(!oldPlugins[item.name].tags || oldPlugins[item.name].tags.indexOf(pluginChecksum) === -1) {

                    item.id = oldPlugins[item.name].id;

                    debug('Update Plugin: ', item);

                    kongClient.plugin.update(item, function (err, updated) {

                        if (err) console.error(err);

                        delete(oldPlugins[item.name]);

                        debug('Plugin %j updated for route: %j', updated, routeId);

                        cb();

                    });

                } else {

                    debug('Plugin is already updated');

                    delete(oldPlugins[item.name]);

                    cb();

                }

            }, function(err) {

                if(oldPlugins.length === 0) return cb();

                deleteOldRoutePlugins(oldPlugins, cb);

            });

        });

    }

    function deleteOldRoutePlugins(plugins, cb) {

        async.eachSeries(plugins, function(item, cb) {

            debug('Deleting plugin: ', item);

            kongClient.plugin.delete(item.id, function(err, deleted) {

                if(err) console.error(err);

                debug('Plugin Deleted');

                cb();

            });

        }, function(err) {

            cb();

        });

    }

    function listRoutePlugins(routeId, offset, result, cb) {

        debug('Listing plugins');

        if(!result) result = {};

        kongClient.plugin.listByRoute(routeId, offset, function(err, plugins) {

            if(err) console.error(err);

            if(!plugins || plugins.data.length === 0) {
                debug('No plugins found');
                return cb();
            }

            async.each(plugins.data, function(item, cb) {

                debug('Plugin: ', item);

                result[item.name] = item;

                cb();

            }, function(err) {

                if(plugins.offset) {
                    debug('Getting next page of routes: ', plugins.offset);
                    return listRoutePlugins(routeId, plugins.offset, result, cb);
                }

                cb(null, result);

            });

        });

    }

    function syncUpstream(cb) {

        debug('Syncing upstream...');

        kongClient.upstream.get(options.upstream.name, function(err, upstream) {

            if(err) {
                return cb(err);
            }

            options.checksum.upstream = checksum(JSON.stringify(options.upstream) + appVersion);

            if(upstream && upstream.tags.indexOf(options.checksum.upstream) > -1) {

                options.upstream = upstream;

                debug('Kong Upstream Found: ', options.upstream);

                cb();

            } else {

                debug('Kong Upstream Not Synced: ', upstream);

                options.upstream.tags.push(options.checksum.upstream);

                kongClient.upstream.updateOrCreate(options.upstream, function(err, created) {

                    if(err) {
                        return cb(err);
                    }

                    if(!created) return cb(new Error('No upstream created'));

                    options.upstream = created;

                    debug('Kong Upstream Created: ', options.upstream);

                    cb();

                });

            }

        });

    }

    function getUpstream(cb) {

        if(options.upstream && options.upstream.id) return cb(null, options.upstream);

        kongClient.upstream.get(options.upstream.name, function(err, upstream) {

            if(err) {
                return cb(err);
            }

            options.checksum.upstream = checksum(JSON.stringify(options.upstream) + appVersion);

            if(!upstream) return cb(new Error('No upstream found on kong'));

            options.upstream = upstream;

            cb(null, upstream);

        });

    }

    function syncTarget(cb) {

        debug('Syncing targets...');

        getUpstream(function(err, upstream) {

            if(err) return cb(err);

            debug('Syncing targets for upstream ' + JSON.stringify(upstream) + '...');

            kongClient.target.list(upstream.id, null, function(err, targets) {

                if(err) {
                    // This is a runtime error, we cannot stop the API startup process at this point, just log the error
                    // on console and monitor
                    console.error(err);

                    return cb();
                }

                if(!targets) targets = {};

                debug('Found targets: ', targets);

                let createIgnore = [];

                async.eachSeries(targets.data, function(item, cb) {

                    if(item.tags.indexOf(options.checksum.upstream) === -1) {

                        debug('Deleting target: ', item);

                        kongClient.target.delete(upstream.name, item.id, function(err, deleted) {

                            if (err) {
                                console.error(err);
                                return cb();
                            }

                            debug('Target deleted');

                            cb();

                        });

                    } else {

                        debug('Valid target: ', item);

                        createIgnore.push(item.target);

                        cb();
                    }

                }, function(err) {

                    // This is a runtime error, we cannot stop the API startup process at this point, just log the error
                    // on console and monitor
                    if(err) console.error(err);

                    createTargets(createIgnore, cb);

                });

            });

        });

    }

    function createTargets(createIgnore, cb) {

        async.eachSeries(options.targets, function(item, cb) {

            item.upstream = options.upstream.name;

            // If no target host:port was specified we get the current machine IP and Loopback configured port
            if(!item.target) {
                debug('Getting IP for target: ', item);
                item.target = ip.address() + ':' + lbConfig.port;
            }

            // If this host is already on Kong with a valid checksum skip create target
            if(createIgnore.indexOf(item.target) > -1) {
                debug('Ignoring target: ', item);
                return setTargetHealthy(item, cb);
            }

            // Add Service checksum to be evaluated on the next deploy
            item.tags.push(options.checksum.upstream);

            debug('Creating target: ', item);

            kongClient.target.create(item, function(err, target) {

                if(err) {
                    console.error(err);
                    return cb();
                }

                debug('Kong Target Created: ', target);

                return setTargetHealthy(item, cb);

            });

        }, function(err) {

            // This is a runtime error, we cannot stop the API startup process at this point, just log the error
            // on console and monitor
            if(err) console.error(err);

            cb();

        });

    }

    function setTargetHealthy(target, cb) {

        debug('Setting Target Healthy: ', target);

        kongClient.target.setHealthy(target.upstream, target.target, function(err, healthy) {

            if(err) {
                console.error(err);
                return cb();
            }

            debug('Target is now Healthy: ', healthy);

            cb();

        });

    }

    function kongBuildRoutes() {

        let apiVersion = lbConfig.restApiRoot;

        let model;
        let methods = [];
        let routes = [];

        for(let m in loopback.registry.modelBuilder.models) {

            if(modelsDefinition[m] && modelsDefinition[m].public === true) {

                if(modelsDefinition[m].kong && modelsDefinition[m].kong.disabled) continue;

                model = loopbackGetActiveRemoteMethods(loopback.registry.modelBuilder.models[m], modelsDefinition[m].options.remoting.sharedMethods);

                for (let method in model) {

                    debug('Method: ', model[method].name);
                    //debug('Method: ', model[method]);

                    if(modelsDefinition[m].kong &&
                        modelsDefinition[m].kong.methods &&
                        modelsDefinition[m].kong.methods[method] &&
                        modelsDefinition[m].kong.methods[method].disabled) continue;

                    methods = [model[method].http.verb.toUpperCase()];
                    if (methods[0] === 'ALL') methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
                    else methods.push("OPTIONS");

                    let basePath = apiVersion + model[method].modelPath + loopbackConvertPath(model[method].http.path);
                    basePath = '/' + basePath.split('/').filter(function(el) { return el; }).join('/');
                    let paths = [
                        basePath,
                        basePath + '/'
                    ];

                    let routeData = {
                        "name": m + '-' + model[method].name,
                        "protocols": [options.service.protocol],
                        "methods": methods,
                        "hosts": options.apiHost,
                        "paths": paths,
                        "regex_priority": 0,
                        "strip_path": false,
                        "preserve_host": true,
                        "tags": [options.service.name, options.upstream.name, m, model[method].name],
                        "plugins": kongBuildRoutePlugins(m, method)
                    };

                    routes.push(routeData);

                }

            }

        }

        return routes;

    }

    function kongBuildRoutePlugins(model, method) {

        let plugins = (options.plugins && JSON.parse(JSON.stringify(options.plugins.route))) || {};

        if(modelsDefinition[model].kong && modelsDefinition[model].kong.plugins) {

            for(let p in modelsDefinition[model].kong.plugins) {
                if(modelsDefinition[model].kong.plugins[p].disabled) delete plugins[p];
                else plugins[p] = JSON.parse(JSON.stringify(modelsDefinition[model].kong.plugins[p]));
            }

        }

        if(modelsDefinition[model].kong &&
            modelsDefinition[model].kong.methods &&
            modelsDefinition[model].kong.methods[method] &&
            modelsDefinition[model].kong.methods[method].plugins) {

            for(let p in modelsDefinition[model].kong.methods[method].plugins) {
                if(modelsDefinition[model].kong.methods[method].plugins[p].disabled) delete plugins[p];
                else plugins[p] = JSON.parse(JSON.stringify(modelsDefinition[model].kong.methods[method].plugins[p]));
            }

        }

        return plugins;

    }

    function loopbackGetActiveRemoteMethods(model, sharedMethods) {
        if(model.sharedClass) {
            const activeRemoteMethods = model.sharedClass
                .methods({includeDisabled: false})
                .reduce((result, sharedMethod) => {
                    if(sharedMethods[sharedMethod.name] === true) {
                        Object.assign(result, {
                            [sharedMethod.name]: {
                                name: sharedMethod.name,
                                accepts: sharedMethod.accepts,
                                returns: sharedMethod.returns,
                                http: sharedMethod.http,
                                modelPath: '/' + model.settings.plural,
                                acl: loopbackGetActiveRemoteMethodsAcl(model, sharedMethod.name)
                            },
                        });
                    }
                    return result;
                }, {});
            return activeRemoteMethods;
        } else {
            return null;
        }
    }

    function loopbackGetActiveRemoteMethodsAcl(model, method) {
        let result = {};
        for( let a in model.settings.acls) {
            if(!model.settings.acls[a].property || model.settings.acls[a].property === method) {
                result[model.settings.acls[a].principalId] = model.settings.acls[a].permission;
            }
        }
        return result;
    }

    function loopbackConvertPath(path) {

        //if(!path) return null;

        let splittedPath = path.split('/');

        for(let p in splittedPath) {

            if(splittedPath[p].indexOf(':') > -1) splittedPath[p] = '[^/]+';

        }

        return splittedPath.join('/');

    }

    function checksum(str, algorithm, encoding) {
        return crypto
            .createHash(algorithm || 'md5')
            .update(str, 'utf8')
            .digest(encoding || 'hex')
    }

    function buildSessionMethods() {

        let apiVersion = lbConfig.restApiRoot;

        loginMethods = [];
        for(let m in options.authentication.loginMethods) {
            loginMethods.push(apiVersion + options.authentication.loginMethods[m]);
        }

        logoutMethods = [];
        for(let m in options.authentication.logoutMethods) {
            logoutMethods.push(apiVersion + options.authentication.logoutMethods[m]);
        }

        return true;

    }

    function syncKongLogin(accessToken, next) {

        debug('Syncing Consumer');

        kongClient.consumer.get(accessToken.userId + '', function(err, consumer) {

            if(err) {
                console.error(err);
                return next(errorFormat(401, 'SYNCKONG_CONSUMERFIND_FAILED', 'Login failed'));
            }

            if(consumer) {
                debug('Consumer already exists');
                return syncKongCredentials(consumer, accessToken, next);
            }

            kongClient.consumer.create({ username: accessToken.userId + '' }, function(err, created) {

                if(err) {
                    console.error(err);
                    return next(errorFormat(401, 'SYNCKONG_CONSUMERCREATE_FAILED', 'Login failed'));
                }

                if(!created) {
                    debug('Consumer not created, returning error');
                    return next(errorFormat(401, 'SYNCKONG_LOGIN_FAILED', 'Login failed'));
                }

                debug('Consumer created');

                syncKongCredentials(created, accessToken, next);

            });

        });

    }

    function syncKongLogout(accessToken, next) {

        console.log('syncKongLogout: ', accessToken);

        kongClient.consumer.deleteKeyAuthCredentials(accessToken.userId, accessToken.id, function(err, deleted) {

            if (err) {
                console.error(err);
                return next(errorFormat(401, 'SYNCKONG_SYNC_FAILED', 'Login failed'));
            }

            debug('deleted: ', deleted);

            next();

        });

    }

    function syncKongCredentials(consumer, accessToken, next) {

        debug('Sync Credentials for consumer: ', consumer);

        kongClient.consumer.listKeyAuthCredentials(consumer.id, function(err, keys) {

            if(err) {
                console.error(err);
                return next(errorFormat(401, 'SYNCKONG_SYNC_FAILED', 'Login failed'));
            }

            if(!keys || !keys.data || keys.data.length === 0) {
                debug('No Previous Keys on Kong');
                return createKongCredentials(consumer, accessToken, next);
            }

            let expiration = new Date();
            expiration.setSeconds(expiration.getSeconds() - parseInt(accessToken.ttl));
            expiration = Math.floor(expiration.getTime() / 1000);

            let credentialsCount = 0;

            async.eachSeries(keys.data, function(item, cb) {

                if(item.created_at > expiration && credentialsCount < options.authentication.simultaneousSessions) {
                    debug('Valid credential');
                    credentialsCount++;
                    return cb();
                }

                debug('Expired credential or exceeded the max simultaneous sessions, deleting credential...');

                kongClient.consumer.deleteKeyAuthCredentials(consumer.id, item.id, cb);

            }, function(err) {

                if(err) console.error(err);

                debug('Creating the latest login credential');

                createKongCredentials(consumer, accessToken, next);

            });

        });

    }

    function createKongCredentials(consumer, accessToken, next) {

        kongClient.consumer.createKeyAuthCredentials(consumer.id, accessToken.id, function(err, credential) {

            if(err) {
                console.error(err);
                return next(errorFormat(401, 'CREATEKONG_LOGIN_FAILED', 'Login failed'));
            }

            debug('Credential created');

            next();

        });

    }

    loopbackApplication.remotes().after('**', (ctx, next) => {

        if(loginMethods.indexOf(ctx.req.originalUrl) > -1 && ctx.result && ctx.result.id) {

            syncKongLogin(ctx.result, next);

        } else if(logoutMethods.indexOf(ctx.req.originalUrl) > -1 && ctx.req && ctx.req.accessToken && ctx.req.accessToken.id) {

            syncKongLogout(ctx.req.accessToken, next);

        } else {
            next();
        }

    });

    function errorFormat(status, code, message) {
        var err = new Error(message);
        err.statusCode = status;
        err.code = code;
        err.statusText = message;
        err.message = message;

        return err;
    }

    init();

};



