class Users::OmniauthCallbacksController < Devise::OmniauthCallbacksController

  # adds skip validation
  skip_before_filter :verify_authenticity_token

  def twitter
    sign_in_with :twitter_login, :twitter
  end

  def facebook
    sign_in_with :facebook_login, :facebook
  end

  def google_oauth2
    sign_in_with :google_login, :google_oauth2
  end

  def saml
    sign_in_with :saml_login, :saml
  end

  def after_sign_in_path_for(resource)
    if resource.registering_with_oauth
      finish_signup_path
    else
      super(resource)
    end
  end

  private

    def sign_in_with(feature, provider)
      raise ActionController::RoutingError.new("Not Found") unless Setting["feature.#{feature}"]

      auth = request.env["omniauth.auth"]

      identity = Identity.first_or_create_from_oauth(auth)


      #if auth.provider == Identity::SAML_PROVIDER
      #  @user = current_user || identity.user || User.first_or_initialize_for_oauth_saml(auth, identity.try(:user))
      #else
      #  @user = current_user || identity.user || User.first_or_initialize_for_oauth(auth)
      #end

      if current_user && auth.provider == Identity::SAML_PROVIDER
            if identity.user.blank? || (identity.user && identity.user_id == current_user.id)
              @user = User.associate_user_oatuh_saml(auth, identity, current_user)
            else
              redirect_to '/associate', notice: 'Usted ya tiene una cuenta asociada a esta plataforma, debe cerrar su sesión actual y loguearse con esa cuenta.'
              return
            end
          else
            if auth.provider == Identity::SAML_PROVIDER
              @user = current_user || User.first_or_initialize_for_oauth_saml(auth, identity.try(:user))
            else
              if identity.user
                @user = identity.user
              else
                @user = current_user || User.first_or_initialize_for_oauth(auth)
              end
            end
          end


      if save_user
        identity.update(user: @user)
        sign_in_and_redirect @user, event: :authentication
        set_flash_message(:notice, :success, kind: provider.to_s.capitalize) if is_navigational_format?
      else
        session["devise.#{provider}_data"] = auth
        redirect_to new_user_registration_url
      end
    end

    def save_user
      @user.save || @user.save_requiring_finish_signup
    end

end
