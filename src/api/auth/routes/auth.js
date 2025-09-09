module.exports = {
  routes: [
    {
      method: "POST",
      path: "/auth/login",
      handler: "auth.login",
      config: {
        auth: false, // allow public access
      },
    },
  ],
};
