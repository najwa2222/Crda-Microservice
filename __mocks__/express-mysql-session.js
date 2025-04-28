export default function(session) {
  return class MockStore extends session.Store {
    constructor(options) {
      super(options);
      
      // Mock database connection for session store
      this.connection = {
        query: () => Promise.resolve([]) // Mock empty result for queries
      };

      // Required session store methods
      this.set = (sid, sessionData, callback) => callback(null);
      this.get = (sid, callback) => callback(null, null);
      this.destroy = (sid, callback) => callback(null);
      this.touch = (sid, sessionData, callback) => callback(null);

      // Event emitter stub
      this.on = () => this;
    }

    // Add optional cleanup method
    close() {
      return Promise.resolve();
    }
  };
};
