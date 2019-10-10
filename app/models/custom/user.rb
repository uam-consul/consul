class User < ApplicationRecord

  devise :omniauthable, :omniauth_providers => [:saml , :facebook, :twitter, :google_oauth2]

  include Verification

  devise :database_authenticatable, :registerable, :confirmable, :recoverable, :rememberable,
         :trackable, :validatable, :omniauthable, :password_expirable, :secure_validatable,
         authentication_keys: [:login]

  acts_as_voter
  acts_as_paranoid column: :hidden_at
  include ActsAsParanoidAliases

  include Graphqlable

  has_one :administrator
  has_one :moderator
  has_one :valuator
  has_one :tracker
  has_one :manager
  has_one :poll_officer, class_name: "Poll::Officer"
  has_one :organization
  has_one :lock
  has_many :flags
  has_many :identities, dependent: :destroy
  has_many :debates, -> { with_hidden }, foreign_key: :author_id
  has_many :proposals, -> { with_hidden }, foreign_key: :author_id
  has_many :people_proposals, -> { with_hidden }, foreign_key: :author_id
  has_many :budget_investments, -> { with_hidden }, foreign_key: :author_id, class_name: "Budget::Investment"
  has_many :comments, -> { with_hidden }
  has_many :failed_census_calls
  has_many :notifications
  has_many :direct_messages_sent,     class_name: "DirectMessage", foreign_key: :sender_id
  has_many :direct_messages_received, class_name: "DirectMessage", foreign_key: :receiver_id
  has_many :legislation_answers, class_name: "Legislation::Answer", dependent: :destroy, inverse_of: :user
  has_many :follows
  has_many :budget_rol_assignments
  has_many :budgets, through: :budget_rol_assignments
  has_many :votation_set_answers
  belongs_to :geozone

  LEVEL_LOGIN = {level_1: 1, level_2: 2, level_3: 3, level_4: 4}

  validates :username, presence: true, if: :username_required?
  validates :username, uniqueness: { scope: :registering_with_oauth }, if: :username_required?
  validates :document_number, uniqueness: { scope: :document_type }, allow_nil: true

  validate :validate_username_length

  validates :official_level, inclusion: {in: 0..5}
  validates :terms_of_service, acceptance: { allow_nil: false }, on: :create

  validates_associated :organization, message: false

  accepts_nested_attributes_for :organization, update_only: true

  attr_accessor :skip_password_validation
  attr_accessor :use_redeemable_code
  attr_accessor :login

  scope :administrators, -> { joins(:administrator) }
  scope :moderators,     -> { joins(:moderator) }
  scope :organizations,  -> { joins(:organization) }
  scope :officials,      -> { where("official_level > 0") }
  scope :male,           -> { where(gender: "male") }
  scope :female,         -> { where(gender: "female") }
  scope :newsletter,     -> { where(newsletter: true) }
  scope :for_render,     -> { includes(:organization) }
  scope :by_document,    ->(document_type, document_number) do
    where(document_type: document_type, document_number: document_number)
  end
  scope :email_digest,   -> { where(email_digest: true) }
  scope :active,         -> { where(erased_at: nil) }
  scope :erased,         -> { where.not(erased_at: nil) }
  scope :public_for_api, -> { all }
  scope :by_comments,    ->(query, topics_ids) { joins(:comments).where(query, topics_ids).distinct }
  scope :by_authors,     ->(author_ids) { where("users.id IN (?)", author_ids) }
  scope :by_username_email_or_document_number, ->(search_string) do
    string = "%#{search_string}%"
    where("username ILIKE ? OR email ILIKE ? OR document_number ILIKE ?", string, string, string)
  end
  scope :between_ages, -> (from, to) do
    where(
      "date_of_birth > ? AND date_of_birth < ?",
      to.years.ago.beginning_of_year,
      from.years.ago.end_of_year
    )
  end

  before_validation :clean_document_number

  # Get the existing user by email if the provider gives us a verified email.
  def self.first_or_initialize_for_oauth(auth)
    oauth_email           = auth.info.email
    oauth_email_confirmed = oauth_email.present? && (auth.info.verified || auth.info.verified_email)
    oauth_user            = User.find_by(email: oauth_email) if oauth_email_confirmed

    if oauth_user
      oauth_user.set_level_one
    end

    oauth_user || User.new(
      username:  auth.info.name || auth.uid,
      email: oauth_email,
      oauth_email: oauth_email,
      password: Devise.friendly_token[0, 20],
      terms_of_service: "1",
      level_login: LEVEL_LOGIN[:level_1],
      confirmed_at: oauth_email_confirmed ? DateTime.current : nil
    )
  end

  # Get the existing user by email if the provider gives us a verified email.
  def self.first_or_initialize_for_oauth_saml(auth, user=nil)
    unless user
      oauth_email           = nil
      oauth_email_confirmed = nil
      oauth_user            = nil
    else
      oauth_user = user
    end

    user_attributes = auth.extra.raw_info.to_h
    oauth_email = user_attributes['eMail'].try(:first)

    # eIdentifier formal: CP/CP/xxxxxxxxxx.... (CP=Código de país, el primero será el del país de origen del identificador, el segundo el del país de destino)
    # En el caso de identificación de ciudadanos españoles o extranjeros residentes, el formato será por tanto ES/ES/[DNI o NIE]

    eIdentifier = user_attributes['eIdentifier'].try(:first)
    oauth_document_number = eIdentifier.slice(6,eIdentifier.length)
    oauth_source_country = eIdentifier.slice(0,2)
    oauth_target_country = eIdentifier.slice(3,2)

    oauth_citizenQAAlevel = user_attributes['citizenQAALevel'].try(:first)
    oauth_isdni = user_attributes['isdnie'].try(:first)

    puts "Auth.uid = #{auth.uid}"

    puts "user atributes =  #{user_attributes}"

    puts "Nombre = #{user_attributes['givenName'].first} #{user_attributes['surname'].first}"

    puts "DNI = #{oauth_document_number}"

    if oauth_user.blank? && !oauth_document_number.blank?
      oauth_user = User.where(document_number: oauth_document_number).first
      if oauth_user
        if (oauth_user.identities.where(provider: Identity::SAML_PROVIDER).count != 0 )
          oauth_user.confirmed_at = DateTime.current
          oauth_user.skip_reconfirmation!
        else
          oauth_user = nil
          oauth_email = nil
        end
      end
    end



   if oauth_user.blank?
     username =  user_attributes['givenName'].first + " " + user_attributes['surname'].first
     user_count = User.where("username like '#{username}%'").count
     #username = [username, user_count.to_s].join('_') if user_count > 0
     #username = username
     unless oauth_email.blank?
          oauth_email_confirmed = DateTime.current
    end
    oauth_user = User.new(
      username:  username,
      email: oauth_email,
      oauth_email: oauth_email,
      password: Devise.friendly_token[0, 20],
      terms_of_service: "1",
      confirmed_at: oauth_email_confirmed ? DateTime.current : nil,
      first_name: user_attributes['givenName'].first,
      last_name: user_attributes['surname'].first,
      #role: user_attributes['http://wso2.org/claims/role'].first,
      #user_certified: user_attributes['http://wso2.org/claims/userCertified'].first == 'true' ? true : false,
      country: oauth_source_country,
      #document: user_attributes['http://wso2.org/claims/document'].first,
      #document_number: user_attributes['eIdentifier'].first,
      document_number: oauth_document_number,
      document_type: '1',
      #user_verified: user_attributes['http://wso2.org/claims/userVerified'].first == 'true' ? true : false,
      # middle_name: user_attributes['http://wso2.org/claims/middleName'].first
       uid: auth.uid,
       provider: Identity::SAML_PROVIDER,
       #uid: user_attributes['eIdentifier'].first,
       verified_at: Date.today
    )
  else
    if auth.extra.raw_info.attributes
      if oauth_user.email != oauth_email
        oauth_user.confirmed_at = DateTime.current
        oauth_user.skip_reconfirmation!
      end
        oauth_user.first_name = user_attributes['givenName'].first
        oauth_user.last_name = user_attributes['surname'].first
        #oauth_user.role = user_attributes['http://wso2.org/claims/role'].first
        #oauth_user.user_certified = user_attributes['http://wso2.org/claims/userCertified'].first == 'true' ? true : false
        #oauth_user.country = user_attributes['http://wso2.org/claims/country'].first
        oauth_user.country = oauth_source_country
        #oauth_user.document = user_attributes['http://wso2.org/claims/document'].first
        #oauth_user.document_number = user_attributes['eIdentifier'].first
        oauth_user.document_number = oauth_document_number
        oauth_user.document_type = '1'
        #oauth_user.user_verified = user_attributes['http://wso2.org/claims/userVerified'].first == 'true' ? true : false
        #oauth_user.middle_name = user_attributes['http://wso2.org/claims/middleName'].first
        oauth_user.uid = auth.uid
        oauth_user.provider = Identity::SAML_PROVIDER
        #oauth_user.uid = user_attributes['eIdentifier'].first
      end
    end
    oauth_user.level_login = oauth_citizenQAAlevel
    oauth_user
  end

  def self.associate_user_oauth_saml(auth, identity, current_user)
      user_attributes = auth.extra.raw_info.to_h
      oauth_user = current_user
      if auth.extra.raw_info.attributes
        oauth_user.first_name = user_attributes['givenName'].try(:first)
        oauth_user.last_name = user_attributes['surname'].try(:first)
        eIdentifier = user_attributes['eIdentifier'].try(:first)
        oauth_document_number = eIdentifier.slice(6,eIdentifier.length)
        oauth_source_country = eIdentifier.slice(0,2)
        oauth_target_country = eIdentifier.slice(3,2)
        oauth_citizenQAAlevel = user_attributes['citizenQAALevel'].try(:first)
        oauth_isdni = user_attributes['isdnie'].try(:first)
        oauth_user.document_type = '1',
        oauth_user.uid = auth.uid,
        oauth_user.provider = Identity::SAML_PROVIDER
        #oauth_user.uid = user_attributes['eIdentifier'].try(:first)
      end
      oauth_user.level_login = oauth_citizenQAAlevel
      oauth_user
    end


    def set_level_one
        self.level_login = LEVEL_LOGIN[:level_1]
        self.residence_verified_at = nil
        #self.level_two_verified_at = nil
        self.verified_at = nil
      end

      def is_level_login_one?
        level_login == 1
      end

      def is_level_login_more_one?
        level_login == 2 || level_login == 3 || level_login == 4
      end

      def text_level_login
        text = ''
        if level_login
          if level_login == 1
            text = "Nivel 1"
          elsif level_login == 2
            text = "Nivel 2"
          elsif level_login == 3
            text = "Nivel 3"
          elsif level_login == 4
            text = "Nivel 4"
          end
        end
        text
      end


  def name
    organization? ? organization.name : username
  end

  def debate_votes(debates)
    voted = votes.for_debates(Array(debates).map(&:id))
    voted.each_with_object({}) { |v, h| h[v.votable_id] = v.value }
  end

  def proposal_votes(proposals)
    voted = votes.for_proposals(Array(proposals).map(&:id))
    voted.each_with_object({}) { |v, h| h[v.votable_id] = v.value }
  end

  def legislation_proposal_votes(proposals)
    voted = votes.for_legislation_proposals(proposals)
    voted.each_with_object({}) { |v, h| h[v.votable_id] = v.value }
  end

  def budget_investment_votes(budget_investments)
    voted = votes.for_budget_investments(budget_investments)
    voted.each_with_object({}) { |v, h| h[v.votable_id] = v.value }
  end

  def comment_flags(comments)
    comment_flags = flags.for_comments(comments)
    comment_flags.each_with_object({}){ |f, h| h[f.flaggable_id] = true }
  end

  def voted_in_group?(group)
    votes.for_budget_investments(Budget::Investment.where(group: group)).exists?
  end

  def headings_voted_within_group(group)
    Budget::Heading.where(id: voted_investments.by_group(group).pluck(:heading_id))
  end

  def voted_investments
    Budget::Investment.where(id: votes.for_budget_investments.pluck(:votable_id))
  end

  def administrator?
    administrator.present?
  end

  def moderator?
    moderator.present?
  end

  def valuator?
    valuator.present?
  end

  def tracker?
    tracker.present?
  end

  def manager?
    manager.present?
  end

  def poll_officer?
    poll_officer.present?
  end

  def organization?
    organization.present?
  end

  def verified_organization?
    organization && organization.verified?
  end

  def official?
    official_level && official_level > 0
  end

  def add_official_position!(position, level)
    return if position.blank? || level.blank?
    update official_position: position, official_level: level.to_i
  end

  def remove_official_position!
    update official_position: nil, official_level: 0
  end

  def has_official_email?
    domain = Setting["email_domain_for_officials"]
    email.present? && ((email.end_with? "@#{domain}") || (email.end_with? ".#{domain}"))
  end

  def display_official_position_badge?
    return true if official_level > 1
    official_position_badge? && official_level == 1
  end

  def block
    debates_ids = Debate.where(author_id: id).pluck(:id)
    comments_ids = Comment.where(user_id: id).pluck(:id)
    proposal_ids = Proposal.where(author_id: id).pluck(:id)
    investment_ids = Budget::Investment.where(author_id: id).pluck(:id)
    proposal_notification_ids = ProposalNotification.where(author_id: id).pluck(:id)

    hide

    Debate.hide_all debates_ids
    Comment.hide_all comments_ids
    Proposal.hide_all proposal_ids
    Budget::Investment.hide_all investment_ids
    ProposalNotification.hide_all proposal_notification_ids
  end

  def erase(erase_reason = nil)
    update(
      erased_at: Time.current,
      erase_reason: erase_reason,
      username: nil,
      email: nil,
      unconfirmed_email: nil,
      phone_number: nil,
      encrypted_password: "",
      confirmation_token: nil,
      reset_password_token: nil,
      email_verification_token: nil,
      confirmed_phone: nil,
      unconfirmed_phone: nil
    )
    identities.destroy_all
  end

  def erased?
    erased_at.present?
  end

  def take_votes_if_erased_document(document_number, document_type)
    erased_user = User.erased.where(document_number: document_number)
                             .where(document_type: document_type).first
    if erased_user.present?
      take_votes_from(erased_user)
      erased_user.update(document_number: nil, document_type: nil)
    end
  end

  def take_votes_from(other_user)
    return if other_user.blank?
    Poll::Voter.where(user_id: other_user.id).update_all(user_id: id)
    Budget::Ballot.where(user_id: other_user.id).update_all(user_id: id)
    Vote.where("voter_id = ? AND voter_type = ?", other_user.id, "User").update_all(voter_id: id)
    data_log = "id: #{other_user.id} - #{Time.current.strftime("%Y-%m-%d %H:%M:%S")}"
    update(former_users_data_log: "#{former_users_data_log} | #{data_log}")
  end

  def locked?
    Lock.find_or_create_by(user: self).locked?
  end

  def self.search(term)
    term.present? ? where("email = ? OR username ILIKE ?", term, "%#{term}%") : none
  end

  def self.username_max_length
    @@username_max_length ||= columns.find { |c| c.name == "username" }.limit || 60
  end

  def self.minimum_required_age
    (Setting["min_age_to_participate"] || 16).to_i
  end

  def show_welcome_screen?
    verification = Setting["feature.user.skip_verification"].present? ? true : unverified?
    sign_in_count == 1 && verification && !organization && !administrator?
  end

  def password_required?
    return false if skip_password_validation
    super
  end

  def username_required?
    !organization? && !erased?
  end

  def email_required?
    !erased? && unverified?
  end

  def locale
    self[:locale] ||= I18n.default_locale.to_s
  end

  def confirmation_required?
    super && !registering_with_oauth
  end

  def send_oauth_confirmation_instructions
    if oauth_email != email
      update(confirmed_at: nil)
      send_confirmation_instructions
    end
    update(oauth_email: nil) if oauth_email.present?
  end

  def name_and_email
    "#{name} (#{email})"
  end

  def age
    Age.in_years(date_of_birth)
  end

  def save_requiring_finish_signup
    begin
      self.registering_with_oauth = true
      save(validate: false)
    # Devise puts unique constraints for the email the db, so we must detect & handle that
    rescue ActiveRecord::RecordNotUnique
      self.email = nil
      save(validate: false)
    end
    true
  end

  def ability
    @ability ||= Ability.new(self)
  end
  delegate :can?, :cannot?, to: :ability

  def public_proposals
    public_activity? ? proposals : User.none
  end

  def public_debates
    public_activity? ? debates : User.none
  end

  def public_comments
    public_activity? ? comments : User.none
  end

  # overwritting of Devise method to allow login using email OR username
  def self.find_for_database_authentication(warden_conditions)
    conditions = warden_conditions.dup
    login = conditions.delete(:login)
    where(conditions.to_hash).where(["lower(email) = ?", login.downcase]).first ||
    where(conditions.to_hash).where(["username = ?", login]).first
  end

  def self.find_by_manager_login(manager_login)
    find_by(id: manager_login.split("_").last)
  end

  def interests
    followables = follows.map(&:followable)
    followables.compact.map { |followable| followable.tags.map(&:name) }.flatten.compact.uniq
  end


  def self.current_user
    Thread.current[:user]
  end

  def self.current_user=(user)
    Thread.current[:user] = user
  end

  def send_devise_notification(notification, *args)
    devise_mailer.send(notification, self, *args).deliver_later
  end

  private

    def clean_document_number
      return unless document_number.present?
      self.document_number = document_number.gsub(/[^a-z0-9]+/i, "").upcase
    end

    def validate_username_length
      validator = ActiveModel::Validations::LengthValidator.new(
        attributes: :username,
        maximum: User.username_max_length)
      validator.validate(self)
    end

end
