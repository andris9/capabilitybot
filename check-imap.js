"use strict";

var imapHandler = require("./imapHandler/imapHandler"),
    net = require("net"),
    tls = require("tls");

module.exports = function(options, callback){
    new IMAPChecker(options, callback).connect();
};

function IMAPChecker(options, callback){
    options = options || {};
    this.host = options.host || "localhost";
    this.port = options.port || (options.ssl ? 993 : 143);
    this.ssl = !!options.ssl;
    this.ignoreSTARTTLS = !!options.ignoreSTARTTLS;

    this.callback = callback;

    this.user = options.user || "";
    this.pass = options.pass || "";

    this.connection = false;

    this.greetingTimeout = false;

    this.capability = {};
    this.logText = [];

    this.remainder = "";
    this.command = "";
    this.literalRemaining = 0;
    this.ignoreData = false;

    this.greeting = true;
    this.currentAction = -1;
    this.actions = [
        {
            payload: "A1 CAPABILITY",

            untagged: untaggedCapability.bind(this, "pre-auth"),

            ok: function(self){
                // if no need to run STARTTLS, skip it and post-starttls capability
                if(self.ssl || self.ignoreSTARTTLS || (self.capability["pre-auth"] || []).indexOf("STARTTLS") < 0){
                    self.currentAction += 2;
                }
                self.nextAction();
            }
        },
        {
            payload: "A2 STARTTLS",
            ok: function(self){
                self.log({type:"connection", payload:"Upgrading connection ..."});
                self.upgradeConnection(function(err){
                    if(err){
                        self.onError(err);
                        return;
                    }
                    self.log({type:"connection", payload:"Connection upgraded"});
                    self.nextAction();
                });
            }
        },
        {
            payload: "A3 CAPABILITY",

            untagged: untaggedCapability.bind(this, "post-starttls"),

            ok: function(self){
                self.nextAction();
            }
        },
        {
            pre: function(self){
                if(!self.user){
                    //skip and shift
                    self.currentAction++;
                    return false;
                }
                return true;
            },

            payload: "A4 LOGIN \"" + this.user + "\" \"" + this.pass + "\"",

            logPayload: "A4 LOGIN \"****\" \"****\"",

            ok: function(self){
                self.nextAction();
            }
        },
        {
            payload: "A5 CAPABILITY",

            untagged: untaggedCapability.bind(this, "post-auth"),

            ok: function(self){
                self.nextAction();
            }
        },
        {
            payload: "A6 LOGOUT"
        }
    ];
}

IMAPChecker.prototype.GREETING_TIMEOUT = 15 * 1000;

IMAPChecker.prototype.connect = function(){
    var sslOptions = {
        rejectUnauthorized: false
    };

    if(this.ssl){
        this.connection = tls.connect(this.port, this.host, sslOptions, this.onConnect.bind(this));
    }else{
        this.connection = net.connect(this.port, this.host, this.onConnect.bind(this));
    }

    this.connection.on("error", this.onError.bind(this));

    this.greetingTimeout = setTimeout(this.handleGreetingTimeout.bind(this), this.GREETING_TIMEOUT);
};

IMAPChecker.prototype.onConnect = function(){
    this.log({type: "connection", payload: "Connection established to " + this.host + " (" + this.connection.remoteAddress + ")"});

    this.connection.on("data", this.onData.bind(this));
    this.connection.on("close", this.onClose.bind(this));
    this.connection.on("end", this.onEnd.bind(this));
};

IMAPChecker.prototype.onEnd = function(){
    this.close();
};

IMAPChecker.prototype.onError = function(err){
    this.error = err;
    this.log({type: "error", payload: err.message});
    this.close();
};

IMAPChecker.prototype.log = function(data){
    this.logText.push(data);
};

IMAPChecker.prototype.close = function(){
    clearTimeout(this.greetingTimeout);

    if(!this.connection){
        if(typeof this.callback == "function" && this.error){
            this.callback(this.error, false, this.logText);
            this.callback = false;
        }
        return;
    }

    var socket = this.connection.socket || this.connection;
    if(socket && !socket.destroyed){
        if(typeof this.callback == "function" && this.error){
            this.callback(this.error, false, this.logText);
            this.callback = false;
        }
        socket.destroy();
    }else{
        if(typeof this.callback == "function" && this.error){
            this.callback(this.error, false, this.logText);
            this.callback = false;
        }
    }

    this.connection = false;
};

IMAPChecker.prototype.onClose = function(){
    this.log({type: "connection", payload: "Connection closed"});

    clearTimeout(this.greetingTimeout);
    this.connection = false;

    if(typeof this.callback == "function"){
        this.callback(this.error || null, this.capability, this.logText);
        this.callback = false;
    }
};

IMAPChecker.prototype.onData = function(chunk){
    clearTimeout(this.greetingTimeout);

    if(this.ignoreData){
        return;
    }

    var match,
        str = (chunk || "").toString("binary");

    if(this.literalRemaining){
        if(this.literalRemaining > str.length){
            this.literalRemaining -= str.length;
            this.command += str;
            return;
        }
        this.command += str.substr(0, this.literalRemaining);
        str = str.substr(this.literalRemaining);
        this.literalRemaining = 0;
    }
    this.remainder = str = this.remainder + str;
    while((match = str.match(/(\{(\d+)(\+)?\})?\r?\n/))){

        if(!match[2]){
            // Now we have a full command line, so lets do something with it
            this.processData(this.command + str.substr(0, match.index));

            this.remainder = str = str.substr(match.index + match[0].length);
            this.command = "";
            continue;
        }

        this.remainder = "";

        this.command += str.substr(0, match.index + match[0].length);

        this.literalRemaining = Number(match[2]);

        str = str.substr(match.index + match[0].length);

        if(this.literalRemaining > str.length){
            this.command += str;
            this.literalRemaining -= str.length;
            return;
        }else{
            this.command += str.substr(0, this.literalRemaining);
            this.remainder = str = str.substr(this.literalRemaining);
            this.literalRemaining = 0;
        }
    }
};

IMAPChecker.prototype.handleGreetingTimeout = function(){
    if(typeof this.callback == "function"){
        this.callback(new Error("Timeout waiting for a greeting"), false, this.logText.length ? this.logText : false);
        this.callback = false;
    }
    this.close();
};

IMAPChecker.prototype.processData = function(data){
    this.log({type: "server", payload: data});

    var command;

    try{
        command = imapHandler.parser(data, {allowUntagged: true});
    }catch(E){
        return this.onError(E);
    }

    // 1st message is a greeting
    if(this.greeting && command.tag == "*"){
        if((command.command || "").toString().trim().toUpperCase() != "OK"){
            return this.onError("Invalid greeting");
        }
        this.greeting = false;
        return this.nextAction();
    }

    var action = this.actions[this.currentAction],
        humanReadable = command.attributes && command.attributes.length && command.attributes[command.attributes.length-1].type == "TEXT" && command.attributes[command.attributes.length-1].value || false;

    // handle tagged response
    if(command.tag == action.tag){
        switch((command.command || "").toString().trim().toUpperCase()){
            case "OK":
                if(typeof action.ok == "function"){
                    action.ok(this);
                }
                break;
            case "NO":
                if(typeof action.no == "function"){
                    action.no(this);
                }else{
                    this.onError(new Error("Unexpected NO" + (humanReadable ? ": " + humanReadable : "")));
                }
                break;
            case "BAD":
                if(typeof action.bad == "function"){
                    action.bad(this);
                }else{
                    this.onError(new Error("Unexpected BAD" + (humanReadable ? ": " + humanReadable : "")));
                }
                break;
            default:
                return this.nextAction();
        }
    }

    // handle untagged responses
    if(command.tag == "*" && typeof action.untagged == "function"){
        action.untagged(this, command);
    }
};

IMAPChecker.prototype.nextAction = function(){
    if(this.currentAction >= this.actions.length - 1){
        return this.close();
    }

    var action = this.actions[++this.currentAction],
        command = imapHandler.parser(action.payload);

    // the command can skip itself if needed
    if(typeof action.pre == "function" && action.pre(this) === false){
        return this.nextAction();
    }

    action.tag = command.tag;

    this.log({type: "client", payload: action.logPayload || action.payload});

    this.connection.write(new Buffer(action.payload + "\r\n", "binary"));
};

IMAPChecker.prototype.upgradeConnection = function(callback){
    this.ignoreData = true;
    this.connection.removeAllListeners("data");
    this.connection.removeAllListeners("error");

    var opts = {
        socket: this.connection,
        host: this.host,
        rejectUnauthorized: true
    };

    this.connection = tls.connect(opts, (function(){
        this.ignoreData = false;
        this.ssl = true;
        this.connection.on("data", this.onData.bind(this));

        return callback(null, true);
    }).bind(this));
    this.connection.on("error", this.onError.bind(this));
};

function untaggedCapability(state, self, command){
    if((command.command || "").toString().trim().toUpperCase() == "CAPABILITY"){
        self.capability[state] = [].concat(command.attributes || []).map(function(capa){
            return (capa.value || "").toString().trim().toUpperCase();
        }).join(" ");
    }
}
