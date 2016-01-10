var child_process = require('child_process');
var _ = require('lodash');

var nip = module.exports = {
    chain: [],
    executable: 'iptables',
    _defaultDeny: false,
    _flush: false
};

nip.flush = function flush() {
    this._flush = true;
    return this;
};

nip.defaultDeny = function defaultDeny() {
    this._defaultDeny = true;
    return this;
};

nip.allow = function allow(options) {

    var options = _.merge(options, {
        'protocol': 'tcp',
        'port': null,
        'cidr_blocks': ['0.0.0.0/0']
    });

    if (options.cidr_blocks.constructor === String)
        options.cidr_blocks = [options.cidr_block];

    _.each(options.cidr_blocks, function(cidr_block) {
        
        var rule = [
            '-A INPUT',
            ['--protocol', options.protocol].join(" "),
            ['--dport', options.port].join(" "),
            ['--source', cidr_block].join(" "),
            ['-m conntrack'],
            ['--ctstate NEW,ESTABLISHED'],
            ['-j ACCEPT']
        ];

        this.chain.push(rule);

    };

    return this;    
};

nip.apply = function apply(options, cb) {

    if (this.flush)
        this.chain.unshift(['-F']); // Flush existing tables

    if (this.defaultDeny)
        this.chain.push(['-P INPUT DROP']); // Drop any packets that slip through the defined rules

    async.mapSeries(this.chain, function (link){
        child_process.spawn(this.executable, link);
    });

    cb();
};
