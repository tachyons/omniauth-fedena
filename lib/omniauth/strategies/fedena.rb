require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Fedena < OmniAuth::Strategies::OAuth2
      option :name, :fedena

      option :client_options, {
        :site => "http://fedena.com",
        :authorize_url => "/oauth/authorize"
      }

      uid { raw_info["username"] }

      info do
        {
          :email => raw_info["email"],
          :user_type => raw_info["user_type"]
        }
      end

      def build_access_token
        Rails.logger.debug "Omniauth build access token"
        options.token_params.merge!(:headers => {'Authorization' => 'Token token=\"%s\"' })
        super
      end

      def raw_info
        @raw_info ||= access_token.get('/api/users/admin').parsed
      end
    end
  end
end
