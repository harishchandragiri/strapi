const jwt = require("jsonwebtoken");

module.exports = (config, { strapi }) => {
  return async (ctx, next) => {
    const authHeader = ctx.request.header.authorization;

    if (!authHeader) {
      return ctx.unauthorized("No authorization header");
    }

    const token = authHeader.replace("Bearer ", "");

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || "super-secret-key");

      // Type guard to ensure decoded is an object and has 'id'
      if (typeof decoded === "object" && decoded !== null && "id" in decoded) {
        const user = await strapi.db.query("plugin::users-permissions.user").findOne({
          where: { id: { $eq: decoded.id } },
        });

        if (!user) {
          return ctx.unauthorized("User not found");
        }

        ctx.state.user = user;
      } else {
        return ctx.unauthorized("Invalid token payload");
      }
    } catch (err) {
      return ctx.unauthorized("Invalid or expired token");
    }

    return next()
}
};