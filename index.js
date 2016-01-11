var child_process = require('child_process');
var _ = require('lodash');
var async = require('async');

var nip = module.exports = {
    chain: [],
    executable: 'iptables'
};

nip._setPolicies = function policies() {
    var self = this;

    // allow all outgoing traffic on any interface (+ wildcard), force to top of table (-I)
    self.chain.push(['-I OUTPUT -o + -d 0.0.0.0/0 -j ACCEPT']);
    self.chain.push(['-I INPUT -i + -m state --state ESTABLISHED,RELATED -j ACCEPT']);

    // allow traffic on loopback interface
    self.chain.unshift(['-A INPUT -i lo -j ACCEPT']);
    self.chain.unshift(['-A OUTPUT -o lo -j ACCEPT']);

    // default INPUT policy
    self.chain.unshift(['--policy INPUT DROP']);

    // set default output and forward policies to ACCEPT
    self.chain.unshift(['--policy OUTPUT ACCEPT']);
    self.chain.unshift(['--policy FORWARD ACCEPT']);

    // Flush existing tables
    self.chain.unshift(['-F']); 
    
};

nip.allow = function allow(options) {
    var self = this;
    
    var options = _.defaults(options, {
        'protocol': 'tcp',
        'port': null,
        'cidr_blocks': ['0.0.0.0/0'],
        'interface': '+' // + is wildcard, optionally restrict to a specific interface (ex: eth0)
    });

    if (options.cidr_blocks.constructor === String)
        options.cidr_blocks = [options.cidr_blocks];

    _.each(options.cidr_blocks, function(cidr_block) {
        
        var inRule = [
            '-A INPUT',
            ['--protocol', options.protocol].join(" "),
            ['--in-interface', options.interface].join(" "),
            ['--dport', options.port].join(" "),
            ['--source', cidr_block].join(" "),
            '--match state',
            '--state NEW,ESTABLISHED',
            '-j ACCEPT'
        ];

        var outRule = [
            '-A OUTPUT',
            ['--protocol', options.protocol].join(" "),
            ['--out-interface', options.interface].join(" "),
            ['--sport', options.port].join(" "),
            ['--destination', cidr_block].join(" "),
            '--match state',
            '--state ESTABLISHED',
            '-j ACCEPT'
        ];

        self.chain.push(inRule);
        self.chain.push(outRule);

    });

    return self;    
};

nip.print = function print() {
    var self = this;

    self._setPolicies();
    _.each(self.chain, function (link){
        console.log([self.executable, link.join(" ")].join(" "));
    });
};
    
nip.apply = function apply(cb) {
    var self = this;
    cb = cb || function() {};

    self._setPolicies();
    async.eachSeries(self.chain, function (link, eachCallback){
        var command = [self.executable, link.join(" ")].join(" ");
        child_process.exec(command, function(err) {
            eachCallback(err); 
        });
    }, function(err) {
        cb(err);
    });
};
