const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

module.exports = {
  async login(ctx) {
    const { identifier, password } = ctx.request.body;

    if (!identifier || !password) {
      return ctx.badRequest("Please provide identifier and password");
    }

    // Find user by email or username
    const user = await strapi.db
      .query("plugin::users-permissions.user")
      .findOne({
        where: {
          $or: [
            { email: identifier.toLowerCase() },
            { username: identifier },
          ],
        },
      });

    if (!user) {
      return ctx.unauthorized("Invalid identifier or password");
    }

    // Validate password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return ctx.unauthorized("Invalid identifier or password");
    }

    // Generate JWT
    const token = jwt.sign(
      { id: user.id },
      process.env.JWT_SECRET || "super-secret-key", // store JWT_SECRET in .env
      { expiresIn: "7d" }
    );

    // Hide password field
    delete user.password;

    return {
      jwt: token,
      user,
    };
  },
};
