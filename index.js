"use strict";

var config = require("./config"),
    checkImap = require("./check-imap"),
    log = require("npmlog"),
    capabilityData = [],
    ejs = require("ejs"),
    processed = false,
    http = require("http"),
    template = require("fs").readFileSync(__dirname + "/template.html").toString("utf-8");

var i = 0;

var processHosts = function(){
    if(i >= config.hosts.length){
        log.info("Status", "All checked");
        processed = true;
        return;
    }

    var host = config.hosts[i++];

    log.info("host", "Checking %s ...", host.name);
    checkImap(host, function(err, capability, transaction){
        capabilityData.push({
            host: host,
            error: err,
            capability: capability,
            transaction: transaction
        });
        if(err){
            log.error("imap", "Result: FAIL")
            log.error("imap", err);
        }else{
            log.info("imap", "Result: SUCCESS");
        }

        if(capability){
            Object.keys(capability).forEach(function(capa){
                log.info(capa, capability[capa]);
            });
        }

        processHosts();
    });
};

processHosts();

http.createServer(function (req, res) {
    res.writeHead(200, {'Content-Type': 'text/html'});
    res.end(ejs.render(template, {
        processed: !!processed,
        capabilityData: capabilityData.sort(function(a, b){
            return a.host.name.toLowerCase().localeCompare(b.host.name.toLowerCase());
        }),
        total: config.hosts.length
    }));
}).listen(config.port, function(){
    log.info("http", "Server listening on port %s", config.port);
});

