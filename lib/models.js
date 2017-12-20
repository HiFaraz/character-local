'use strict';

/**
 * Module dependencies.
 */
const { OK, UNAUTHORIZED } = require('http-codes');
const { compare: compareHash, hash: generateHash } = require('bcryptjs');
const Sequelize = require('sequelize');
const createError = require('http-errors');

const saltRounds = 12; // TODO read this from config, don't hardcode this

module.exports = config => {
  const models = {
    user: {
      attributes: DataTypes => ({
        password: {
          allowNull: false,
          type: Sequelize.STRING,
        },
        username: {
          allowNull: false,
          type: Sequelize.STRING,
        },
      }),
      define: User => {
        /**
         * Authenticate a username and password
         *
         * @param {string} username
         * @param {string} password
         * @return {Promise<Object>}
         */
        User.authenticate = async (username, password) => {
          const user = await User.findOne({
            attributes: ['id', 'password'],
            where: { username },
          });
          if (user && (await compareHash(password, user.password))) {
            return {
              id: user.id,
            };
          } else {
            // either user does not exist, or password is incorrect
            /**
             * Send a status of `UNAUTHORIZED` instead of `NOT_FOUND`, even if user
             * does not exist
             *
             *
             * This is **NOT** a fool-proof security measure because other parts of
             * the application may reveal whether a username exists, such as a
             * sign-up page or public profile page
             */
            throw createError(UNAUTHORIZED, 'Unable to authenticate');
          }
        };

        /**
         * Hash passwords when creating a new user
         *
         * @param {Object} user
         * @param {string} user.username
         * @param {string} user.password
         * @return {Promise<Object>} Sequelize model instance
         */
        User.create = async user => {
          if (user.username === '' || user.password === '') {
            throw new Error('Empty username and/or password');
          }

          const result = {};

          try {
            // Object.getPrototypeOf(User).create.call(User, ...) calls the original User.create method
            const created = await Object.getPrototypeOf(User).create.call(
              User,
              Object.assign({}, user, {
                password: await generateHash(user.password, saltRounds),
              }),
            );
            result.id = created.id;
            result.status = OK;
          } catch (error) {
            if (error instanceof Sequelize.UniqueConstraintError) {
              throw new Error('Username already exists');
            } else {
              throw error;
            }
          }

          return result;
        };

        // TODO need a class method to change a user's password
      },
      options: {
        indexes: [
          {
            fields: ['username'],
            unique: true,
          },
        ],
      },
    },
  };

  if (config && config.table && config.table.trim() !== '') {
    models.user.options.tableName = config.table; // TODO somehow this needs to respect the namespacing for plugin and authenticator tables
  }

  return models;
};
