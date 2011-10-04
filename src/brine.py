#!/usr/bin/python2.7

import crypto
import cPickle as pickle

class Brine(object):
    
    def dumps(self, obj, pickler=pickle):
        """pickle and encrypt a python object"""
        return self.encrypt(self.PICKLE_PAD + pickler.dumps(obj))

    def loads(self, data, pickler=pickle):
        """decrypt and unpickle a python object"""
        data = self.decrypt(data)
        # simple integrity check to verify that we got meaningful data
        assert data.startswith(self.PICKLE_PAD), "unexpected header"
        return pickler.loads(data[len(self.PICKLE_PAD):])