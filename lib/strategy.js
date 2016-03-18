var util = require('util');
var OAuth2Strategy = require('passport-oauth2');
var InternalOAuthError = require('passport-oauth2').InternalOAuthError;


/**
 * `Strategy` constructor.
 *
 * The Unsplash authentication strategy authenticates requests by delegating to
 * Unsplash using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Unsplash Application ID
 *   - `clientSecret`  your Unsplash Secret
 *   - `callbackURL`   URL to which Unsplash will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new UnsplashStrategy({
 *         clientID: 'Application ID',
 *         clientSecret: 'Secret'
 *         callbackURL: 'https://www.example.net/auth/unsplash/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
    options = options || {};
    options.authorizationURL = options.authorizationURL || 'https://unsplash.com/oauth/authorize';
    options.tokenURL = options.tokenURL || 'https://unsplash.com/oauth/token';
  
    OAuth2Strategy.call(this, options, verify);
    this.name = 'unsplash';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);


/**
 * Retrieve user profile from Unsplash.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `unsplash`
 *   - `id`               the user's Unsplash ID
 *   - `name`             the user's name
 *   - `username`         the user's Unsplash username
 *   - `avatar`           the URL of the avatar for the user on Unsplash
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {
    this._oauth2.get('https://api.unsplash.com/me', accessToken, function (err, body, res) {
        if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }

        try {
            var json = JSON.parse(body);

            var profile = {
                provider: 'unsplash',
                id: json.uid,
                name: {
                    first_name: json.first_name,
                    last_name: json.last_name
                },
                username: json.username,
                avatar: json.profile_image,
                _raw: body,
                _json: json,
            };

            done(null, profile);
        } catch(e) {
            done(e);
        }
    });
}


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;