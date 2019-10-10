class Users::SessionsController < Devise::SessionsController

  def destroy
    # Preserve the saml_uid in the session
    saml_uid = session["saml_uid"]
    saml_session_index = session["saml_session_index"]
    super do
      session["saml_uid"] = saml_uid
      session["saml_session_index"] = saml_session_index
    end
  end


  private

    def after_sign_in_path_for(resource)
      #if !verifying_via_email? && resource.show_welcome_screen?
      if resource.show_welcome_screen?
        welcome_path
      else
        super
      end
    end

    def after_sign_out_path_for(resource)
      request.referer.present? && !request.referer.match("management") ? request.referer : super
    end

    def verifying_via_email?
      return false if resource.blank?
      stored_path = session[stored_location_key_for(resource)] || ""
      stored_path[0..5] == "/email"
    end

    def after_sign_out_path_for(resource)
      if session['saml_uid']
        session.delete(:saml_uid)
        #user_saml_omniauth_authorize_path + "/spslo"
        request.referer.present? && !request.referer.match("management") ? request.referer : super
      else
        super
    end
  end

end
