const bcrypt = require("bcryptjs");

async function test() {
    const plainPassword = "radwa123";  // The password you entered
    const hashedPassword = "$2b$10$/1AJmqXgO1NBYh0.SfHCXuAQL0918mucceHKTZiEy1cB3b32tJfv."; // The stored hash

    console.log("Entered Password:", plainPassword);
    console.log("Stored Hash:", hashedPassword);

    const isMatch = await bcrypt.compare(plainPassword, hashedPassword);
    console.log("Password Match Result:", isMatch);
}

test();
