
Examples
========

We start with a simple example. Before we proceed 
let setup `virtualenv`_ environment::

    $ virtualenv env
    $ env/bin/easy_install wheezy.security[pycrypto]


Protecting Information
----------------------

Let assume we would like protect some sensitive information, e.g. user id. We
can encrypt it, add hash to proove validity and finally say that this
value is valid for 20 minutes only::

    from wheezy.security.crypto import Ticket
    
    ticket = Ticket(max_age=1200, salt='p5sArbHFZvxgeEJFrM9h')

Once you have ticket you can encode any string::

    protected_value = ticket.encode('hello')
    
Decode ``protected_value`` this way::

    value = ticket.decode(protected_value)
    
User Principal
--------------

Ticket can be used to protect user principal over network (e.g. in http 
cookie)::
    
    from wheezy.security import Principal

    principal = Principal(
            id='125134788', 
            roles=['user'], 
            alias='John Smith')
    secure_value = ticket.encode(principal.dump())
    
Server side now restores this information::

    from wheezy.security import ANONYMOUS
    from wheezy.security import Principal

    principal_dump = ticket.decode(secure_value)
    if principal_dump:
        principal = Principal.load(principal_dump)
    else:
        principal = ANONYMOUS

.. _`virtualenv`: http://pypi.python.org/pypi/virtualenv
