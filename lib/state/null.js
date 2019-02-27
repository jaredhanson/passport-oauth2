function NullStore() {
}

NullStore.prototype.store = function store(req, cb) {
  cb();
};

NullStore.prototype.verify = function verify(req, providedState, cb) {
  cb(null, true);
};


module.exports = NullStore;
