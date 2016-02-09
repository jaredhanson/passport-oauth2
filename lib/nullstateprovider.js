function NullStateStore(options) {
}

NullStateStore.prototype.get = function(req, cb) {
  cb();
}

NullStateStore.prototype.verify = function(req, providedState, cb) {
  cb();
}


module.exports = NullStateStore;