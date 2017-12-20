'use strict';

/**
 * Module dependencies.
 */

const {
  INTERNAL_SERVER_ERROR,
  SEE_OTHER,
  UNAUTHORIZED,
} = require('http-codes');
const Authenticator = require('character-authenticator/post');
// const PassportAdapter = require('character-passport/post');
const asyncpipe = require('asyncpipe');
const createError = require('http-errors');
const models = require('./models');

// TODO make this a separate module that can be used to apply Passport strategies
void class PassportStrategyAuthenticator {
  async authenticate({ req, res }) {
    return new Promise((resolve, reject) => {
      if (!this.strategy) {
        return reject(
          createError(INTERNAL_SERVER_ERROR, 'Passport strategy not defined'),
        );
      }

      const strategy = Object.create(this.strategy);

      /**
       * Augment the strategy
       */

      strategy.error = function (error) {
        error.statusCode = error.statusCode || INTERNAL_SERVER_ERROR;
        reject(createError(error));
      };

      strategy.fail = function (challenge, status = UNAUTHORIZED) {
        const _status = typeof challenge === 'number' ? challenge : status;

        reject(createError(_status, 'Unable to authenticate'));
      };

      // redirects should only happen on a GET request based authenticator
      // NOTE: this function is taken from Passport.js code
      strategy.redirect = function (url, status) {
        // NOTE: Do not use `res.redirect` from Express, because it can't decide
        //       what it wants.
        //
        //       Express 2.x: res.redirect(url, status)
        //       Express 3.x: res.redirect(status, url) -OR- res.redirect(url, status)
        //         - as of 3.14.0, deprecated warnings are issued if res.redirect(url, status)
        //           is used
        //       Express 4.x: res.redirect(status, url)
        //         - all versions (as of 4.8.7) continue to accept res.redirect(url, status)
        //           but issue deprecated versions

        res.statusCode = status || 302;
        res.setHeader('Location', url);
        res.setHeader('Content-Length', '0');
        res.end();
        // resolve(); // TODO is this required?
      };

      strategy.success = function (user, info = {}) {
        resolve({ account: Object.assign({ _info: info }, user), req, res });
      };

      strategy.authenticate(req, res);
    });
  }
};

module.exports = class LocalAuthenticator extends Authenticator {
  /**
   * Handles requests from the hub to the authenticator
   *
   * @param {Object} context
   * @param {IncomingMessage} context.req
   * @param {ServerResponse} context.res
   * @return {Promise<Object>}
   */
  async authenticate({ req, res }) {
    // errors are handled upstream by the Authentication plugin
    return {
      account: await this.models.User.authenticate(
        req.body.username,
        req.body.password,
      ),
      req,
      res,
    };
  }

  /**
   * Define extra authenticator routes
   */
  extend() {
    // Add open registration route if enabled
    if (this.config.registrationOpen) {
      const registrationPath = '/register';

      // session middleware needed if login after registration enabled
      if (this.config.loginAfterRegistration) {
        this.router.post(registrationPath, this.deps.session);
      }

      // add registration middleware
      this.router.post(registrationPath, async (req, res, next) => {
        try {
          await asyncpipe(register, onboard, login, () =>
            res.redirect(
              SEE_OTHER,
              this.config.registrationRedirect || this.config.successRedirect,
            ),
          )({
            User: this.models.User,
            authenticator: this,
            req,
            res,
          });
        } catch (error) {
          return res.redirect(
            SEE_OTHER,
            this.config.registrationFailureRedirect ||
            this.config.failureRedirect,
          );
        }
      });
    }
  }

  static defaults() {
    return {
      loginAfterRegistration: true,
      registrationOpen: true,
    };
  }

  static models(config) {
    return models(config);
  }
};

/**
 * Login the user after registration if enabled
 *
 * @param {Object} context
 * @return {Promise<Object>}
 */
async function login(context) {
  // login the user if enabled
  if (context.authenticator.config.loginAfterRegistration) {
    context.req.login({
      authenticator: {
        account: { id: context.account.id },
        name: context.authenticator.name,
      },
      id: context.identity.id,
    }); // TODO feels like I have to remember a complex interface whenever I want to login, fix this
  }
  return context;
}

/**
 * Onboard the authenticator account by creating a new core identity
 *
 * @param {Object} context
 * @return {Promise<Object>}
 */
async function onboard(context) {
  const identity = await context.authenticator.onboard({
    id: context.account.id,
    username: context.account.username, // the function doesn't need this, but it is passed so that it gets emitted for auditing
  }); // create a new core identity
  return Object.assign({ identity }, context);
}

/**
 * Register username and password
 *
 * @param {Object} context
 * @return {Promise<Object>}
 */
async function register(context) {
  const account = await context.User.create({
    password: context.req.body.password,
    username: context.req.body.username,
  });
  return Object.assign(
    { account: { id: account.id, username: context.req.body.username } },
    context,
  );
}
