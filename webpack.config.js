/**
 * webpack.config.js
 * Kintone ICカード紛失対応プラグイン ビルド設定
 * IPA ガイドライン準拠・セキュリティ強化
 * 
 * @author Kei-Adachi0709
 * @version 1.0.0
 * @date 2025-06-19
 */

const path = require('path');
const KintonePlugin = require('@kintone/webpack-plugin-kintone-plugin');

module.exports = {
  mode: process.env.NODE_ENV || 'development',
  entry: {
    desktop: './src/js/desktop.js',
    config: './src/js/config/config.js'
  },
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'js/[name].js',
    libraryTarget: 'commonjs2'
  },
  target: 'web',
  resolve: {
    extensions: ['.js'],
    fallback: {
      crypto: false,
      fs: false,
      path: false
    }
  },
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: [
              ['@babel/preset-env', {
                targets: {
                  browsers: ['> 1%', 'last 2 versions', 'ie >= 11']
                },
                modules: 'commonjs'
              }]
            ],
            plugins: [
              '@babel/plugin-proposal-class-properties'
            ]
          }
        }
      },
      {
        test: /\.css$/,
        use: ['style-loader', 'css-loader']
      }
    ]
  },
  plugins: [
    new KintonePlugin({
      manifestJSONPath: './manifest.json',
      privateKeyPath: './private.ppk',
      pluginZipPath: './dist/plugin.zip'
    })
  ],
  optimization: {
    minimize: process.env.NODE_ENV === 'production',
    splitChunks: {
      cacheGroups: {
        vendor: {
          test: /[\\/]node_modules[\\/]/,
          name: 'vendors',
          chunks: 'all'
        }
      }
    }
  },
  externals: {
    kintone: 'kintone'
  },
  devtool: process.env.NODE_ENV === 'development' ? 'source-map' : false,
  performance: {
    hints: 'warning',
    maxEntrypointSize: 500000,
    maxAssetSize: 500000
  }
};
