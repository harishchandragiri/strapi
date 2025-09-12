const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

module.exports = {
  async login(ctx) {
    const { identifier, password } = ctx.request.body;

    if (!identifier || !password) return ctx.badRequest("Provide identifier and password");

    const user = await strapi.db.query("plugin::users-permissions.user").findOne({
      where: {
        $or: [
          { email: identifier.toLowerCase() },
          { username: identifier }
        ],
      },
    });

    if (!user) return ctx.unauthorized("Invalid identifier or password");

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return ctx.unauthorized("Invalid identifier or password");

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET || "super-secret-key", { expiresIn: "7d" });

    delete user.password;

    // ctx.cookies.set("jwt", token, {
    //   httpOnly: true,
    //   secure: process.env.NODE_ENV === "production",
    //   sameSite: "lax", // for localhost dev
    //   maxAge: 7 * 24 * 60 * 60 * 1000,
    //   path: "/",
    // });

    return  {
      jwt: token,
      user,
    };
  },

  async logout(ctx) {
    ctx.cookies.set("jwt", null, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 0,
      path: "/",
    });

    return { message: "Logout successful" };
  },
};
