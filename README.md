# Roblox Audio Whitelister

Nodejs tool to mass whitelist audio assets for games

## Features

- Bulk whitelist audio assets from a specific group
- Automatic rate limit handling with exponential backoff
- Concurrent processing for faster whitelisting
- Error handling and retry mechanisms

## Prerequisites

- Node.js installed on your system
- A Roblox account with appropriate permissions
- Access to the group containing the audio assets
- Permission to modify the target universe/game

## Configuration Guide

### Getting Required Information

1. **ROBLOSECURITY Cookie:**
   - copy your roblosecurity cookie from the owner of the game

2. **Universe ID:**
   - Open the game's page on Roblox Create page and copy the Universe ID

3. **Group ID:**
   - Open your group's page on Roblox
   - The Group ID is the number in the URL after "groups/"
   - Example: https://www.roblox.com/groups/1234567/Group-Name (1234567 is the Group ID)

4. **Add Collaborator in studio**
   - On Studio, add yourself (the owner of the group) to collaborator in the game in order to successfully whitelist audio

## Usage

1. After setting up the config.json file, run the tool:
   ```bash
   npm start
   ```

2. The tool will:
   - Authenticate using your provided cookie
   - Fetch all audio assets from the specified group
   - Whitelist each audio for use in your universe
   - Handle any rate limits automatically
   - Display progress in the console

## Important Notes

- Keep your .ROBLOSECURITY cookie private and never share it
- The tool processes up to 50 audio assets concurrently
- Rate limits are handled automatically with up to 10 retries
- Make sure you have the necessary permissions in both the group and universe

## Error Handling

The tool includes built-in error handling for common issues:
- Rate limiting (429 errors)
- Authentication failures
- Network errors
- Invalid permissions

## Contributing

Feel free to submit issues and pull requests to improve the tool.

## License

ISC License

## Disclaimer

This tool is not officially affiliated with Roblox. Use at your own risk and ensure compliance with Roblox's Terms of Service.