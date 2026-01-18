import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      callbackURL: process.env.GOOGLE_CALLBACK_URL!,
    },
    async (_accessToken, _refreshToken, profile, done) => {
      const email = profile.emails?.[0]?.value?.toLowerCase() || null;

      // ENFORCE domain restriction: only @nitdgp.ac.in accounts [web:742]
      if (!email || !email.endsWith("@nitdgp.ac.in")) {
        return done(null, false, {
          message: "Use your @nitdgp.ac.in account to register",
        });
      }

      return done(null, {
        googleSub: profile.id,
        displayName: profile.displayName,
        email,
      });
    }
  )
);

export default passport;
