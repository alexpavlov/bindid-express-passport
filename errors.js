class IllegalStateError extends Error {}
class InvalidCredentialsError extends Error {}
class DuplicateBindIDAccountError extends Error {}

module.exports = {
    IllegalStateError,
    InvalidCredentialsError,
    DuplicateBindIDAccountError
}