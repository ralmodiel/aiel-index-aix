Rails.application.routes.draw do
  root 'home#index'
  get '/about', to: 'pages#about'
  resources :users, only: [:index, :show] do
    member do
      post :activate
    end
    resources :posts
  end
  namespace :admin do
    resources :orders, except: [:destroy]
    get 'stats', to: 'dashboard#stats'
  end
  resource :profile
end
