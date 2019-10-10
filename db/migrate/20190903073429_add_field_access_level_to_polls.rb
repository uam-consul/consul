class AddFieldAccessLevelToPolls < ActiveRecord::Migration[5.0]
  def change
    add_column :polls, :access_level, :integer, default: 3
  end
end
