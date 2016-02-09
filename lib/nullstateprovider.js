function NullStateStore(options) {
}

NullStateStore.prototype.get = function(req, cb) {
  cb();
}

NullStateStore.prototype.verify = function(req, providedState, cb) {
  cb(null, true);
}


module.exports = NullStateStore;