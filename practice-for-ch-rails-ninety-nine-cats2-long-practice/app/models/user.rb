class User < ApplicationRecord
    validates :username, :session_token, :password_digest, presence :true
    validates :username, :session_token, uniqueness :true

    attr_reader :password
    before_validation :ensure_session_token

    def self.find_by_credentials(username, password)
        user = User.find_by(username: username)
        (user && user.is_password?(password)) ? user : nil
    end

    def password=(password)
        @password = password
        self.password_digest = BCrypt::Password.create(password)
    end

    def is_password?(password)
        password_object = BCrypt::Password.new(self.password_digest)
        password_digest.is_password?(password)
    end

    private

    def generate_unique_session_token
        self.session_token = SecureRandom::urlsafe_base64
    end

    def reset_session_token!
        self.session_token = SecureRandom::urlsafe_base64
        self.save!
        self.session_token
    end

    def ensure_session_token
        self.session_token ||= SecureRandom::urlsafe_base64
    end
end
