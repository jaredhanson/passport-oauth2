function NullStore(options) {
}

NullStore.prototype.get = function(req, cb) {
  cb();
}

NullStore.prototype.verify = function(req, providedState, cb) {
  cb(null, true);
}


module.exports = NullStore;
