
### niptables

Simple but opinionated manipulation of iptables for securing a server

**CAUTION: This sets a default DROP policy on any incoming packets. Make sure to properly allow your ssh port, or you may lock yourself out of your server**

```js
var nip = require('niptables');

nip
    .allow({'port': '22'})  // Allow ssh from anywhere (tcp from '0.0.0.0/0')
    .allow({
        'protocol': 'tcp',
        'port': '8080',
        'cidr_blocks': ['10.0.0.0/16']  // or a list of explicit cidr blocks
    })
    .allow({
        'port': '8000:8001'  // also can specify a range of ports
    })
    .apply(function(err){

        if(err)
            console.log(err);

    });
```

For debugging you can terminate with `print()` instead of `apply(cb)` to see the exact rules that will be applied:

```js
nip
    .allow({'port': '22'})  // Allow ssh from anywhere (tcp from '0.0.0.0/0')
    .print();
```

Output:

```
iptables -F
iptables --policy FORWARD ACCEPT
iptables --policy OUTPUT ACCEPT
iptables --policy INPUT DROP
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT --protocol tcp --dport 22 --source 0.0.0.0/0 --match state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT --protocol tcp --sport 22 --destination 0.0.0.0/0 --match state --state ESTABLISHED -j ACCEPT
iptables -I OUTPUT -o + -d 0.0.0.0/0 -j ACCEPT
iptables -I INPUT -i + -m state --state ESTABLISHED,RELATED -j ACCEPT
```

Notice that rules for all loopback traffic and all external traffic are added by default
