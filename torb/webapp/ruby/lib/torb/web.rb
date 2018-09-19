require 'json'
require 'sinatra/base'
require 'erubi'
require 'mysql2'
require 'mysql2-cs-bind'
require 'pry'

module Torb
  class Web < Sinatra::Base
    configure :development do
      require 'sinatra/reloader'
      register Sinatra::Reloader
    end

    set :root, File.expand_path('../..', __dir__)
    set :sessions, key: 'torb_session', expire_after: 3600
    set :session_secret, 'tagomoris'
    set :protection, frame_options: :deny

    set :erb, escape_html: true

    set :login_required, ->(value) do
      condition do
        if value && !get_login_user
          halt_with_error 401, 'login_required'
        end
      end
    end

    set :admin_login_required, ->(value) do
      condition do
        if value && !get_login_administrator
          halt_with_error 401, 'admin_login_required'
        end
      end
    end

    before '/api/*|/admin/api/*' do
      content_type :json
    end

    helpers do
      def db
        Thread.current[:db] ||= Mysql2::Client.new(
          host: ENV['DB_HOST'],
          port: ENV['DB_PORT'],
          username: ENV['DB_USER'],
          password: ENV['DB_PASS'],
          database: ENV['DB_DATABASE'],
          database_timezone: :utc,
          cast_booleans: true,
          reconnect: true,
          init_command: 'SET SESSION sql_mode="STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION"',
        )
      end

      def get_events(all: false)
        events = if all
          db.query('SELECT * FROM events ORDER BY id ASC')
        else
          db.query('SELECT * FROM events WHERE public_fg = 1 ORDER BY id ASC')
        end.to_a

        events = get_events_from_ids(nil, events: events, without_detail: true)

        events
      end


      def get_event(event_id, login_user_id = nil, event: nil)
        event ||= db.xquery('SELECT * FROM events WHERE id = ?', event_id).first
        return unless event

        event_id ||= event['id']

        # zero fill
        event['total']   = 0
        event['remains'] = 0
        event['sheets'] = {}
        %w[S A B C].each do |rank|
          event['sheets'][rank] = { 'total' => 0, 'remains' => 0, 'detail' => [], 'price' => 0 }
        end

sql = <<SQL
SELECT sheets.*, r.event_id, r.user_id, r.reserved_at, r.canceled_at
FROM sheets
LEFT OUTER JOIN (
  SELECT * 
  FROM reservations 
  WHERE event_id = ? 
  AND canceled_at IS NULL 
  GROUP BY event_id, sheet_id 
  HAVING reserved_at = MIN(reserved_at)
) as r ON r.sheet_id = sheets.id
ORDER BY sheets.rank
SQL
        statement = db.prepare(sql.gsub("\n"," "))
        result = statement.execute(event_id).to_a
        statement.close

        event['total'] = result.size
        
        event['remains'] = result.select { |row| row['reserved_at'].nil? }.size

        result_with_rank = result.group_by {|row| row['rank'] }
        %w[S A B C].each do |rank|
          event['sheets'][rank] = {
            'total' => result_with_rank[rank].size,
            'remains' => result_with_rank[rank].select {|row| row['reserved_at'].nil? }.size,
            'price' => event['price'] + result_with_rank[rank].first['price'],
            'detail' => []
          }
        end

        result.each do |row|
          row['mine'] = login_user_id == row['user_id']
          row['reserved'] = !row['reserved_at'].nil?
          row['reserved_at'] = row['reserved_at']&.to_i
          
          # TODO: 全部消せてるかわからん
          row.delete('canceled_at')
          row.delete('event_id')
          row.delete('id')
          row.delete('price')
          row.delete('user_id')
          event['sheets'][row['rank']]['detail'] << row
        end
      
        event['public'] = event.delete('public_fg')
        event['closed'] = event.delete('closed_fg')

        %w[S A B C].each do |rank|
          event['sheets'][rank]['detail'].sort_by!{|x| x['num']}
        end
        event
      end

      
      def get_events_from_ids(event_ids, login_user_id = nil, events: nil, without_detail: false)
        events ||= db.xquery("SELECT * FROM events WHERE id IN (#{event_ids.join(", ")}) ORDER BY FIELD(id,#{event_ids.join(", ")})").to_a

        event_ids ||= events.map {|row| row['id']}
  
        # zero fill
        events.each do |event|
          event['total']   = 0
          event['remains'] = 0
          event['sheets'] = {}
          %w[S A B C].each do |rank|
            event['sheets'][rank] = { 'total' => rank_to_count(rank), 'remains' => 0, 'detail' => [], 'price' => 0 }
          end
        end
  
sql = <<SQL
SELECT sheets.*, r.event_id, r.user_id, r.reserved_at, r.canceled_at
FROM sheets
LEFT OUTER JOIN (
  SELECT * 
  FROM reservations 
  WHERE event_id IN (#{event_ids.join(", ")})
  AND canceled_at IS NULL 
  GROUP BY event_id, sheet_id 
  HAVING reserved_at = MIN(reserved_at)
) as r ON r.sheet_id = sheets.id
ORDER BY sheets.rank
SQL
        result_with_event_id = db.query(sql.gsub("\n"," ")).to_a.group_by {|row| row['event_id']}
        events.each do |event|
          event['total'] = 1000
        end
        
        events.each do |event|
          event['remains'] = 1000 - (result_with_event_id[event['id']] || {}).select { |row| row['reserved_at'] }.size
        end

        events.each do |event|
          result_with_rank = (result_with_event_id[event['id']] || {}).group_by {|row| row['rank'] }  
          %w[S A B C].each do |rank|
            event['sheets'][rank] = {
              'total' => rank_to_count(rank),
              'remains' => rank_to_count(rank) - (result_with_rank[rank] || {}).select {|row| row['reserved_at'] }.size,
              'price' => event['price'] + rank_to_price(rank),
              'detail' => []
            }
          end
        end

        if without_detail
          events.each do |event|
            %w[S A B C].each do |rank|
              event['sheets'][rank].delete('detail')
            end
          end
        else
          events.each do |event|
            result = result_with_event_id[event['id']]
  
            result.each do |row|
              row['mine'] = login_user_id == row['user_id']
              row['reserved'] = !row['reserved_at'].nil?
              row['reserved_at'] = row['reserved_at']&.to_i
  
              row.delete('canceled_at')
              row.delete('event_id')
              row.delete('id')
              #row.delete('price')
              row.delete('user_id')
              event['sheets'][row['rank']]['detail'] << row
            end
          end
  
          events.each do |event|
            %w[S A B C].each do |rank|
              event['sheets'][rank]['detail'].sort_by!{|x| x['num']}
            end
          end
        end

        events.each do |event|
          event['public'] = event.delete('public_fg')
          event['closed'] = event.delete('closed_fg')
        end

        events
      end

      def rank_to_count(rank)
        case rank
        when "S" 
          50
        when "A" 
          150
        when "B" 
          300
        when "C" 
          500
        end
      end

      def rank_to_price(rank)
        case rank
        when "S"
          5000
        when "A"
          3000
        when "B"
          1000
        when "C"
          0
        end
      end

      def sanitize_event(event)
        sanitized = event.dup  # shallow clone
        sanitized.delete('price')
        sanitized.delete('public')
        sanitized.delete('closed')
        sanitized
      end

      def get_login_user
        return unless session[:user_id]
        db.xquery('SELECT id, nickname FROM users WHERE id = ?', session[:user_id]).first
      end

      def get_login_administrator
        return unless session['administrator_id']
        db.xquery('SELECT id, nickname FROM administrators WHERE id = ?', session['administrator_id']).first
      end

      def validate_rank(rank)
        db.xquery('SELECT COUNT(*) AS total_sheets FROM sheets WHERE `rank` = ?', rank).first['total_sheets'] > 0
      end

      def body_params
        @body_params ||= JSON.parse(request.body.tap(&:rewind).read)
      end

      def halt_with_error(status = 500, error = 'unknown')
        halt status, { error: error }.to_json
      end

      def render_report_csv(reports_body)
        headers({
          'Content-Type'        => 'text/csv; charset=UTF-8',
          'Content-Disposition' => 'attachment; filename="report.csv"',
        })
        reports_body
      end
    end

    get '/' do
      @user   = get_login_user
      @events = get_events.map(&method(:sanitize_event))
      erb :index
    end

    get '/initialize' do
      system "../../db/init.sh"

      status 204
    end

    post '/api/users' do
      nickname   = body_params['nickname']
      login_name = body_params['login_name']
      password   = body_params['password']

      db.query('BEGIN')
      begin
        duplicated = db.xquery('SELECT * FROM users WHERE login_name = ?', login_name).first
        if duplicated
          db.query('ROLLBACK')
          halt_with_error 409, 'duplicated'
        end

        db.xquery('INSERT INTO users (login_name, pass_hash, nickname) VALUES (?, SHA2(?, 256), ?)', login_name, password, nickname)
        user_id = db.last_id
        db.query('COMMIT')
      rescue => e
        warn "rollback by: #{e}"
        db.query('ROLLBACK')
        halt_with_error
      end

      status 201
      { id: user_id, nickname: nickname }.to_json
    end

    get '/api/users/:id', login_required: true do |user_id|
      user = db.xquery('SELECT id, nickname FROM users WHERE id = ?', user_id).first
      if user['id'] != get_login_user['id']
        halt_with_error 403, 'forbidden'
      end

      rows = db.xquery('SELECT r.*, s.rank AS sheet_rank, s.num AS sheet_num FROM reservations r INNER JOIN sheets s ON s.id = r.sheet_id WHERE r.user_id = ? ORDER BY IFNULL(r.canceled_at, r.reserved_at) DESC LIMIT 5', user['id'])
      events_with_id = get_events_from_ids(rows.map {|row| row['event_id']}.uniq).group_by {|row| row['id']}
      recent_reservations = rows.map do |row|
        event = events_with_id[row['event_id']].first
        price = event['sheets'][row['sheet_rank']]['price']
        event.delete('sheets')
        event.delete('total')
        event.delete('remains')

        {
          id:          row['id'],
          event:       event,
          sheet_rank:  row['sheet_rank'],
          sheet_num:   row['sheet_num'],
          price:       price,
          reserved_at: row['reserved_at'].to_i,
          canceled_at: row['canceled_at']&.to_i,
        }
      end

      user['recent_reservations'] = recent_reservations
      user['total_price'] = db.xquery('SELECT IFNULL(SUM(e.price + s.price), 0) AS total_price FROM reservations r INNER JOIN sheets s ON s.id = r.sheet_id INNER JOIN events e ON e.id = r.event_id WHERE r.user_id = ? AND r.canceled_at IS NULL', user['id']).first['total_price']

      rows = db.xquery('SELECT event_id FROM reservations WHERE user_id = ? GROUP BY event_id ORDER BY MAX(IFNULL(canceled_at, reserved_at)) DESC LIMIT 5', user['id'])
      user['recent_events'] = get_events_from_ids(rows.map {|row| row['event_id']}, without_detail: true)

      user.to_json
    end


    post '/api/actions/login' do
      login_name = body_params['login_name']
      password   = body_params['password']

      user      = db.xquery('SELECT * FROM users WHERE login_name = ?', login_name).first
      pass_hash = db.xquery('SELECT SHA2(?, 256) AS pass_hash', password).first['pass_hash']
      halt_with_error 401, 'authentication_failed' if user.nil? || pass_hash != user['pass_hash']

      session['user_id'] = user['id']

      user = get_login_user
      user.to_json
    end

    post '/api/actions/logout', login_required: true do
      session.delete('user_id')
      status 204
    end

    get '/api/events' do
      get_events.map(&method(:sanitize_event)).to_json
    end

    get '/api/events/:id' do |event_id|
      user = get_login_user || {}
      event = get_event(event_id, user['id'])
      halt_with_error 404, 'not_found' if event.nil? || !event['public']

      sanitize_event(event).to_json
    end

    post '/api/events/:id/actions/reserve', login_required: true do |event_id|
      rank = body_params['sheet_rank']

      user  = get_login_user
      event = get_event(event_id, user['id'])
      halt_with_error 404, 'invalid_event' unless event && event['public']
      halt_with_error 400, 'invalid_rank' unless validate_rank(rank)

      sheet = nil
      reservation_id = nil
      loop do
        sheet = db.xquery('SELECT * FROM sheets WHERE id NOT IN (SELECT sheet_id FROM reservations WHERE event_id = ? AND canceled_at IS NULL FOR UPDATE) AND `rank` = ? ORDER BY RAND() LIMIT 1', event['id'], rank).first
        halt_with_error 409, 'sold_out' unless sheet
        db.query('BEGIN')
        begin
          db.xquery('INSERT INTO reservations (event_id, sheet_id, user_id, reserved_at) VALUES (?, ?, ?, ?)', event['id'], sheet['id'], user['id'], Time.now.utc.strftime('%F %T.%6N'))
          reservation_id = db.last_id
          db.query('COMMIT')
        rescue => e
          db.query('ROLLBACK')
          warn "re-try: rollback by #{e}"
          next
        end

        break
      end

      status 202
      { id: reservation_id, sheet_rank: rank, sheet_num: sheet['num'] }.to_json
    end

    delete '/api/events/:id/sheets/:rank/:num/reservation', login_required: true do |event_id, rank, num|
      user  = get_login_user
      event = get_event(event_id, user['id'])
      halt_with_error 404, 'invalid_event' unless event && event['public']
      halt_with_error 404, 'invalid_rank'  unless validate_rank(rank)

      sheet = db.xquery('SELECT * FROM sheets WHERE `rank` = ? AND num = ?', rank, num).first
      halt_with_error 404, 'invalid_sheet' unless sheet

      db.query('BEGIN')
      begin
        reservation = db.xquery('SELECT * FROM reservations WHERE event_id = ? AND sheet_id = ? AND canceled_at IS NULL GROUP BY event_id HAVING reserved_at = MIN(reserved_at) FOR UPDATE', event['id'], sheet['id']).first
        unless reservation
          db.query('ROLLBACK')
          halt_with_error 400, 'not_reserved'
        end
        if reservation['user_id'] != user['id']
          db.query('ROLLBACK')
          halt_with_error 403, 'not_permitted'
        end

        db.xquery('UPDATE reservations SET canceled_at = ? WHERE id = ?', Time.now.utc.strftime('%F %T.%6N'), reservation['id'])
        db.query('COMMIT')
      rescue => e
        warn "rollback by: #{e}"
        db.query('ROLLBACK')
        halt_with_error
      end

      status 204
    end

    get '/admin/' do
      @administrator = get_login_administrator
      @events = get_events(all: true) if @administrator

      erb :admin
    end

    post '/admin/api/actions/login' do
      login_name = body_params['login_name']
      password   = body_params['password']

      administrator = db.xquery('SELECT * FROM administrators WHERE login_name = ?', login_name).first
      pass_hash     = db.xquery('SELECT SHA2(?, 256) AS pass_hash', password).first['pass_hash']
      halt_with_error 401, 'authentication_failed' if administrator.nil? || pass_hash != administrator['pass_hash']

      session['administrator_id'] = administrator['id']

      get_login_administrator.to_json
    end

    post '/admin/api/actions/logout', admin_login_required: true do
      session.delete('administrator_id')
      status 204
    end

    get '/admin/api/events', admin_login_required: true do
      events = get_events(all: true)
      events.to_json
    end

    post '/admin/api/events', admin_login_required: true do
      title  = body_params['title']
      public = body_params['public'] || false
      price  = body_params['price']

      db.query('BEGIN')
      begin
        db.xquery('INSERT INTO events (title, public_fg, closed_fg, price) VALUES (?, ?, 0, ?)', title, public, price)
        event_id = db.last_id
        db.query('COMMIT')
      rescue
        db.query('ROLLBACK')
      end

      get_event(event_id)&.to_json
    end

    get '/admin/api/events/:id', admin_login_required: true do |event_id|
      event = get_event(event_id)
      halt_with_error 404, 'not_found' unless event

      event.to_json
    end

    post '/admin/api/events/:id/actions/edit', admin_login_required: true do |event_id|
      public = body_params['public'] || false
      closed = body_params['closed'] || false
      public = false if closed

      event = get_event(event_id)
      halt_with_error 404, 'not_found' unless event

      if event['closed']
        halt_with_error 400, 'cannot_edit_closed_event'
      elsif event['public'] && closed
        halt_with_error 400, 'cannot_close_public_event'
      end

      db.query('BEGIN')
      begin
        db.xquery('UPDATE events SET public_fg = ?, closed_fg = ? WHERE id = ?', public, closed, event['id'])
        db.query('COMMIT')
      rescue
        db.query('ROLLBACK')
      end

      get_event(event_id).to_json
    end

    get '/admin/api/reports/events/:id/sales', admin_login_required: true do |event_id|
      event = get_event(event_id)

      reservations = db.xquery('SELECT r.*, s.rank AS sheet_rank, s.num AS sheet_num, s.price AS sheet_price, e.price AS event_price FROM reservations r INNER JOIN sheets s ON s.id = r.sheet_id INNER JOIN events e ON e.id = r.event_id WHERE r.event_id = ? ORDER BY reserved_at ASC FOR UPDATE', event['id'])
      keys = %i[reservation_id event_id rank num price user_id sold_at canceled_at]
      body = keys.join(',') << "\n"

      reservations.each do |reservation|
        body << "#{reservation['id'].to_s},#{event['id']},#{reservation['sheet_rank']},#{reservation['sheet_num']},#{reservation['event_price'] + reservation['sheet_price']},#{reservation['user_id']},#{reservation['reserved_at'].iso8601},#{reservation['canceled_at']&.iso8601 || ''}\n"
      end

      render_report_csv(body)
    end

    get '/admin/api/reports/sales', admin_login_required: true do
      reservations = db.query('SELECT r.*, s.rank AS sheet_rank, s.num AS sheet_num, s.price AS sheet_price, e.id AS event_id, e.price AS event_price FROM reservations r INNER JOIN sheets s ON s.id = r.sheet_id INNER JOIN events e ON e.id = r.event_id ORDER BY reserved_at ASC FOR UPDATE')
      keys = %i[reservation_id event_id rank num price user_id sold_at canceled_at]
      body = keys.join(',') << "\n"

      reports = reservations.map do |reservation|
        body << "#{reservation['id']},#{reservation['event_id']},#{reservation['sheet_rank']},#{reservation['sheet_num']},#{reservation['event_price'] + reservation['sheet_price']},#{reservation['user_id']},#{reservation['reserved_at'].iso8601},#{reservation['canceled_at']&.iso8601 || ''}\n"
      end

      render_report_csv(body)
    end
  end
end
