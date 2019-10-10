class AddFieldLevelLoginToUsers < ActiveRecord::Migration[5.0]
  def change
    add_column :users, :level_login, :integer, default: 1
  end
end
